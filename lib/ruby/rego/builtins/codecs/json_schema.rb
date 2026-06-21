# frozen_string_literal: true

require "json"
require "re2"
require "strscan"

module Ruby
  module Rego
    module Builtins
      module Codecs
        # A pure-Ruby JSON Schema engine matching OPA 1.17's json.verify_schema / json.match_schema, which
        # wrap Go's xeipuuv/gojsonschema. gojsonschema is a non-standard, permissive multi-draft validator
        # (draft-04/06/07) — e.g. it enforces const, if/then/else, contains and propertyNames yet, when
        # validating a document, still honours draft-04's boolean exclusiveMinimum. No conformant validator
        # reproduces it, so the engine is hand-rolled here.
        #
        # Only the BOOLEAN result is contractually byte-exact with OPA; the error strings are best-effort
        # (gojsonschema's exact Go locale wording is not reproduced — a documented divergence). verify_schema
        # checks a schema's well-formedness (this file); match_schema validates a document against it.
        # rubocop:disable Metrics/ModuleLength
        # :reek:TooManyConstants -- the keyword tables plus the RE2 construct patterns are distinct data.
        module JsonSchema
          # The seven JSON Schema primitive type names a `type` keyword may name.
          SCHEMA_TYPES = %w[null boolean object array number integer string].freeze

          # Keywords whose value is a single subschema (gojsonschema also accepts a boolean for the two
          # `additional*` ones; that is handled in subschema_error).
          SUBSCHEMA_KEYWORDS = %w[additionalProperties additionalItems propertyNames not if then else
                                  contains].freeze
          # Keywords whose value is an object mapping names to subschemas. `$defs` is deliberately absent:
          # xeipuuv targets draft-04/06/07, so it never validates the draft-2019 `$defs` (an unknown
          # keyword), and a malformed `$defs` subschema therefore does not make the schema invalid.
          SUBSCHEMA_MAP_KEYWORDS = %w[properties patternProperties definitions].freeze
          # Keywords whose value is an array of subschemas (an empty array is accepted).
          SUBSCHEMA_LIST_KEYWORDS = %w[allOf anyOf oneOf].freeze
          # Keywords whose value must be a JSON number (any number, including negative/zero).
          NUMBER_KEYWORDS = %w[minimum maximum].freeze
          # Keywords whose value must be a non-negative integer.
          NON_NEGATIVE_INT_KEYWORDS = %w[minLength maxLength minItems maxItems minProperties
                                         maxProperties].freeze

          # A bare `\C` escape (preceded by an even run of backslashes, so its `\` is a real escape, not
          # inside a `\\` literal). C++ RE2 accepts `\C` (match-any-byte); Go's `regexp` — what gojsonschema
          # uses — rejects it, so it is filtered out after the RE2 compile check. The `*+` possessive
          # quantifier makes the backslash-run scan non-backtracking (linear, ReDoS-safe on untrusted input).
          GO_REJECTED_ESCAPE = /(?<!\\)(?:\\\\)*+\\C/
          # One JSON string literal, for the comment scan below (quote, escapes-or-non-quote bytes, quote).
          JSON_STRING_TOKEN = /"(?:\\.|[^"\\])*"/

          # Verify that `value` (the Rego Value for the schema argument) is a valid JSON schema.
          # @param value [Ruby::Rego::Value]
          # @return [Array(bool, String?)] [valid, error] — error is nil when valid.
          # :reek:NilCheck
          def self.verify(value)
            schema, error = load_schema(value)
            return [false, error] unless error.nil?

            valid_schema(schema)
          end

          # Resolve the schema argument to a Ruby value (object or boolean), or an error. A string is JSON
          # parsed; an object is used directly; any other Rego type is rejected. Mirrors gojsonschema's
          # loader: a non-string/non-object scalar is "wrong type", an array (or a string that parses to a
          # non-object) is "schema is invalid".
          # @return [Array(Object?, String?)]
          def self.load_schema(value)
            case value
            when StringValue then parse_schema_string(value.value)
            when ObjectValue then [value.to_ruby, nil]
            when ArrayValue then [nil, "jsonschema: schema is invalid"]
            else [nil, "jsonschema: wrong type, expected string or object"]
            end
          end
          private_class_method :load_schema

          # A schema passed as a JSON string: parsed, then it must be an object or boolean (a JSON schema).
          # Ruby's JSON.parse accepts `//` and `/* */` comments that Go's encoding/json (gojsonschema's
          # string loader) rejects, so a structural comment is treated as invalid first. (JSON.parse also
          # caps nesting at 100 — NestingError, a ParserError — a documented gem-wide divergence where OPA
          # parses arbitrarily deep.)
          # :reek:TooManyStatements
          def self.parse_schema_string(string)
            return [nil, "jsonschema: invalid JSON string"] unless usable_json_encoding?(string)
            return [nil, "jsonschema: invalid JSON string"] if contains_json_comment?(string)

            parsed = JSON.parse(string)
            return [parsed, nil] if parsed.is_a?(Hash) || [true, false].include?(parsed)

            [nil, "jsonschema: schema is invalid"]
          rescue JSON::ParserError
            [nil, "jsonschema: invalid JSON string"]
          end
          private_class_method :parse_schema_string

          # A string the comment scanner can safely consume: ascii-compatible and valid in its encoding,
          # so StringScanner#scan with an ASCII/UTF-8 regexp cannot raise. A string that fails this is not
          # valid JSON to OPA anyway, so it is reported as invalid rather than scanned.
          def self.usable_json_encoding?(string)
            string.encoding.ascii_compatible? && string.valid_encoding?
          end
          private_class_method :usable_json_encoding?

          # True when `//` or `/* */` appears in STRUCTURAL position (not inside a string value). A `"..."`
          # token is consumed whole (honouring `\"` escapes) so a comment-like sequence inside a string
          # value is not mistaken for a comment opener.
          def self.contains_json_comment?(string)
            scanner = StringScanner.new(string)
            until scanner.eos?
              next if scanner.scan(/#{JSON_STRING_TOKEN}/o)
              return true if scanner.scan(%r{//|/\*})

              scanner.getch
            end
            false
          end
          private_class_method :contains_json_comment?

          # A parsed schema value's well-formedness. A boolean is a valid schema (matches all / nothing); an
          # object is validated keyword by keyword; anything else is invalid.
          # @return [Array(bool, String?)]
          # :reek:NilCheck
          def self.valid_schema(schema)
            return [true, nil] if [true, false].include?(schema)
            return [false, "jsonschema: schema is invalid"] unless schema.is_a?(Hash)

            error = schema_error(schema, schema, Set.new)
            error.nil? ? [true, nil] : [false, "jsonschema: #{error}"]
          end

          # The first well-formedness error in an object (sub)schema, or nil. `root` is the whole document
          # (for `$ref` resolution) and `visited` is the set of `$ref`s already followed on this path (for
          # cycle tolerance). A `$ref` to an in-document fragment is handled specially (see fragment_error):
          # gojsonschema validates the resolved target and a direct `definitions` sibling but suppresses the
          # other keywords. A root ref (`#`/empty) is valid and does NOT suppress; an unresolvable ref is an
          # error. Unknown keywords are ignored.
          # @return [String, nil]
          # :reek:TooManyStatements :reek:NilCheck
          def self.schema_error(schema, root, visited)
            if schema.key?("$ref")
              kind, target = resolve_ref(schema["$ref"], root)
              return "$ref does not resolve" if kind == :error
              return fragment_error(schema, target, root, visited) if kind == :fragment
            end

            keyword_walk(schema, root, visited)
          end
          private_class_method :schema_error

          # :reek:NilCheck
          def self.keyword_walk(schema, root, visited)
            schema.each do |keyword, value|
              error = keyword_error(keyword, value, schema, root, visited)
              return error unless error.nil?
            end
            nil
          end
          private_class_method :keyword_walk

          # A fragment `$ref` node. On the FIRST time a given `$ref` string is seen, gojsonschema replaces the
          # node with the resolved target: this validates the target as a subschema (transitively) and a
          # direct `definitions` sibling, while suppressing the node's other keywords. Any LATER occurrence of
          # the same `$ref` — whether reached on the active path (a cycle) or via a separate branch (a plain
          # repeat) — is not replaced; gojsonschema instead validates that node's OWN keywords (so a repeat
          # does NOT suppress, matching opa eval). `visited` is a global Set of the `$ref`s already replaced,
          # threaded by reference; routing every later occurrence through keyword_walk both reproduces that
          # behaviour and keeps a ref DAG linear (a repeat re-walks only the small ref node, never re-follows
          # the target). Verified byte-exact against opa across ordered/repeated/cyclic ref cases.
          # :reek:NilCheck :reek:LongParameterList :reek:TooManyStatements
          def self.fragment_error(schema, target, root, visited)
            ref = schema["$ref"]
            return keyword_walk(schema, root, visited) if visited.include?(ref)

            visited.add(ref)
            error = subschema_error(target, root, visited)
            return error unless error.nil?

            definitions = schema["definitions"]
            definitions.nil? ? nil : subschema_map_error("definitions", definitions, root, visited)
          end
          private_class_method :fragment_error

          # rubocop:disable Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/AbcSize
          # The well-formedness error for one keyword/value pair, or nil. `$ref` is handled in schema_error,
          # so it is skipped here. Grouped by the shape gojsonschema requires for the keyword's value.
          # :reek:TooManyStatements :reek:LongParameterList
          def self.keyword_error(keyword, value, schema, root, visited)
            case keyword
            when "type" then type_error(value)
            when "multipleOf" then multiple_of_error(value)
            when "pattern" then pattern_error(value)
            when "required" then string_array_error(value, "required", unique: true)
            when "enum" then enum_error(value)
            when "format" then string_error(value, "format")
            when "exclusiveMinimum" then exclusive_error(value, schema, "minimum")
            when "exclusiveMaximum" then exclusive_error(value, schema, "maximum")
            when "items" then items_error(value, root, visited)
            when "dependencies" then dependencies_error(value, root, visited)
            when "uniqueItems" then boolean_error(value, "uniqueItems")
            when *SUBSCHEMA_KEYWORDS then subschema_error(value, root, visited)
            when *SUBSCHEMA_MAP_KEYWORDS then subschema_map_error(keyword, value, root, visited)
            when *SUBSCHEMA_LIST_KEYWORDS then subschema_list_error(value, keyword, root, visited)
            when *NUMBER_KEYWORDS then number_error(keyword, value)
            when *NON_NEGATIVE_INT_KEYWORDS then non_negative_int_error(keyword, value)
            end
          end
          private_class_method :keyword_error
          # rubocop:enable Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/AbcSize

          # `type` is a known type name, or an array of distinct known type names (an empty array is
          # accepted by gojsonschema; duplicates, or any non-type-name element such as null, are rejected).
          def self.type_error(value)
            return type_array_error(value) if value.is_a?(Array)

            SCHEMA_TYPES.include?(value) ? nil : "has a primitive type that is NOT VALID -- given: /#{value}/"
          end
          private_class_method :type_error

          def self.type_array_error(value)
            return "type has an invalid primitive type" unless value.all? { |name| SCHEMA_TYPES.include?(name) }
            return "type items must be distinct" unless value.uniq.length == value.length

            nil
          end
          private_class_method :type_array_error

          # `multipleOf` is a number strictly greater than 0.
          def self.multiple_of_error(value)
            return "multipleOf must be of a Number" unless numeric?(value)

            value.positive? ? nil : "multipleOf must be strictly greater than 0"
          end
          private_class_method :multiple_of_error

          # `pattern` is a string compilable under Go's RE2 (no lookaround/backrefs/...).
          def self.pattern_error(value)
            return "pattern must be of type string" unless value.is_a?(String)

            re2_compatible?(value) ? nil : "pattern must be a valid regex"
          end
          private_class_method :pattern_error

          # An array of distinct strings (`required`), or any array of strings (`dependencies` member,
          # unique: false). gojsonschema rejects duplicates in `required` and `enum` but not in dependency
          # arrays.
          # :reek:ControlParameter
          def self.string_array_error(value, keyword, unique:)
            return "#{keyword} must be of an array" unless value.is_a?(Array)
            return "#{keyword} items must be strings" unless value.all?(String)
            return "#{keyword} items must be distinct" if unique && value.uniq.length != value.length

            nil
          end
          private_class_method :string_array_error

          # `enum` is a non-empty array of distinct values (any JSON value; distinctness is by JSON equality).
          def self.enum_error(value)
            return "enum must be of an array" unless value.is_a?(Array)
            return "enum items must be distinct" unless value.uniq.length == value.length

            nil
          end
          private_class_method :enum_error

          # `exclusiveMinimum`/`exclusiveMaximum`: a number (always), or a boolean only when its paired
          # `minimum`/`maximum` is also present (the draft-04 form, which gojsonschema still accepts at
          # schema-validation time); anything else is invalid.
          def self.exclusive_error(value, schema, paired)
            return nil if numeric?(value)
            return nil if [true, false].include?(value) && schema.key?(paired)

            "exclusive bound must be a number"
          end
          private_class_method :exclusive_error

          # `items` is a subschema or an array of subschemas.
          def self.items_error(value, root, visited)
            return subschema_list_error(value, "items", root, visited) if value.is_a?(Array)

            subschema_error(value, root, visited)
          end
          private_class_method :items_error

          # `dependencies` is an object whose values are subschemas or arrays of strings.
          # :reek:NilCheck
          def self.dependencies_error(value, root, visited)
            return "dependencies must be of type object" unless value.is_a?(Hash)

            value.each_value do |dep|
              error = dependency_error(dep, root, visited)
              return error unless error.nil?
            end
            nil
          end
          private_class_method :dependencies_error

          def self.dependency_error(dep, root, visited)
            return string_array_error(dep, "dependencies", unique: false) if dep.is_a?(Array)

            subschema_error(dep, root, visited)
          end
          private_class_method :dependency_error

          # A single subschema slot: a boolean, or a valid (sub)schema.
          # :reek:NilCheck
          def self.subschema_error(value, root, visited)
            return nil if [true, false].include?(value)
            return "must be a valid schema" unless value.is_a?(Hash)

            schema_error(value, root, visited)
          end
          private_class_method :subschema_error

          # An object-of-subschemas keyword. For patternProperties the keys are RE2 regexes too.
          # :reek:NilCheck :reek:TooManyStatements :reek:LongParameterList
          def self.subschema_map_error(keyword, value, root, visited)
            return "#{keyword} must be of type object" unless value.is_a?(Hash)

            value.each do |name, subschema|
              return "Invalid regex pattern '#{name}'" if keyword == "patternProperties" && !re2_compatible?(name)

              error = subschema_error(subschema, root, visited)
              return error unless error.nil?
            end
            nil
          end
          private_class_method :subschema_map_error

          # An array-of-subschemas keyword (allOf/anyOf/oneOf/items-array).
          # :reek:NilCheck :reek:LongParameterList
          def self.subschema_list_error(value, keyword, root, visited)
            return "#{keyword} must be an array" unless value.is_a?(Array)

            value.each do |subschema|
              error = subschema_error(subschema, root, visited)
              return error unless error.nil?
            end
            nil
          end
          private_class_method :subschema_list_error

          def self.number_error(keyword, value)
            numeric?(value) ? nil : "#{keyword} must be of a Number"
          end
          private_class_method :number_error

          # :reek:NilCheck
          def self.non_negative_int_error(keyword, value)
            return "#{keyword} must be of an integer" unless value.is_a?(Integer)
            return nil if value >= 0

            "#{keyword} must be greater than or equal to 0"
          end
          private_class_method :non_negative_int_error

          def self.string_error(value, keyword)
            value.is_a?(String) ? nil : "#{keyword} must be of type string"
          end
          private_class_method :string_error

          def self.boolean_error(value, keyword)
            [true, false].include?(value) ? nil : "#{keyword} must be of a boolean"
          end
          private_class_method :boolean_error

          # A JSON number (Integer or Float; Ruby booleans are not Numeric).
          def self.numeric?(value)
            value.is_a?(Numeric)
          end
          private_class_method :numeric?

          # A sentinel distinct from any JSON value, for "JSON pointer step not found".
          NOT_FOUND = Object.new
          private_constant :NOT_FOUND

          # Classify a `$ref` value as gojsonschema resolves it against the document `root`, returning
          # [kind, target]:
          #   [:root, nil]        — `#` or the empty string (the whole document); valid, does NOT suppress.
          #   [:fragment, target] — a `#/json/pointer` resolving to an object or boolean node; the caller
          #                         validates `target` and suppresses the other siblings.
          #   [:error, nil]       — a non-string, an external/relative ref, or a fragment that does not
          #                         resolve to a schema node (missing, or pointing at a scalar/array).
          # :reek:NilCheck :reek:TooManyStatements
          def self.resolve_ref(ref, root)
            return [:error, nil] unless ref.is_a?(String)
            return [:root, nil] if ref.empty? || ref == "#"
            return [:error, nil] unless ref.start_with?("#/")

            target = resolve_pointer(ref[1..].to_s, root)
            schema_node?(target) ? [:fragment, target] : [:error, nil]
          end
          private_class_method :resolve_ref

          # Walk a JSON pointer ("/a/b") from `root`, returning the node or NOT_FOUND. ~1/~0 are unescaped.
          # :reek:TooManyStatements
          def self.resolve_pointer(pointer, root)
            node = root
            pointer.split("/", -1).drop(1).each do |token|
              key = token.gsub("~1", "/").gsub("~0", "~")
              node = pointer_step(node, key)
              return NOT_FOUND if node.equal?(NOT_FOUND)
            end
            node
          end
          private_class_method :resolve_pointer

          # :reek:NilCheck
          def self.pointer_step(node, key)
            case node
            when Hash then node.key?(key) ? node[key] : NOT_FOUND
            when Array then array_index(node, key)
            else NOT_FOUND
            end
          end
          private_class_method :pointer_step

          # :reek:NilCheck
          def self.array_index(node, key)
            index = Integer(key, exception: false)
            index && index >= 0 && index < node.length ? node[index] : NOT_FOUND
          end
          private_class_method :array_index

          # A node a `$ref` may resolve to: an object or boolean schema (not a scalar, array or NOT_FOUND).
          def self.schema_node?(node)
            node.is_a?(Hash) || node == true || node == false
          end
          private_class_method :schema_node?

          # Whether `pattern` compiles under the regex engine gojsonschema uses. OPA wraps Go's `regexp`,
          # which is a port of Google's RE2; the re2 gem binds the same C++ RE2 library, so `ok?` answers
          # "would gojsonschema accept this pattern?" exactly — far more faithfully than approximating RE2
          # with Ruby's Onigmo. `log_errors: false` silences RE2's stderr on a rejected pattern. The one
          # construct C++ RE2 accepts but Go's regexp rejects, `\C`, is filtered out. A non-string or
          # invalid-encoding pattern is rejected up front (RE2 returns false on it without raising, but the
          # explicit guard keeps the contract clear).
          def self.re2_compatible?(pattern)
            return false unless pattern.is_a?(String) && pattern.valid_encoding?

            RE2::Regexp.new(pattern, log_errors: false).ok? && !pattern.match?(GO_REJECTED_ESCAPE)
          end
          private_class_method :re2_compatible?
        end
        # rubocop:enable Metrics/ModuleLength
      end
    end
  end
end
