# frozen_string_literal: true

require_relative "json_schema"

module Ruby
  module Rego
    module Builtins
      module Codecs
        # Document validation for OPA 1.17's json.match_schema, layered on the schema-validity engine in
        # json_schema.rb. match_schema(document, schema) -> [match, errors]: `match` is true (errors empty)
        # when the document validates against the schema, else false. As with verify_schema, only the
        # BOOLEAN `match` is byte-exact with OPA's gojsonschema; the errors array is best-effort (a single
        # placeholder entry whose presence — empty vs non-empty — is the contract, not its gojsonschema
        # `{desc,error,field,type}` content/count). The `format` keyword is a no-op here (a documented
        # interim divergence); its assertions land in a follow-up.
        #
        # Like gojsonschema, validation applies every keyword from draft-04/06/07 at once (boolean and
        # numeric exclusiveMinimum, const, if/then/else, contains, propertyNames, …). A pattern is matched
        # with the re2 gem (Go's regex engine), not Ruby's Onigmo.
        module JsonSchema
          # The best-effort error returned when a document does not match (gojsonschema returns one richly
          # typed object per failure; only the array's non-emptiness is contractual).
          MATCH_ERROR = { "desc" => "document does not match schema", "error" => "(root): does not match",
                          "field" => "(root)", "type" => "match" }.freeze

          # @param document_value [Ruby::Rego::Value]
          # @param schema_value [Ruby::Rego::Value]
          # @return [Array(bool, Array), Symbol] [match, errors], or :undefined when the schema or document
          #   argument is not usable (wrong type, malformed JSON string, or a schema that is not well-formed
          #   — gojsonschema returns undefined in all of these).
          # :reek:NilCheck :reek:TooManyStatements
          def self.match(document_value, schema_value)
            schema, schema_error = load_schema(schema_value)
            return :undefined unless schema_error.nil?
            return :undefined unless valid_schema(schema).first

            document, document_error = load_document(document_value)
            return :undefined unless document_error.nil?

            # A document or schema nested past Matcher::MAX_DEPTH throws past the recursion; treat as
            # undefined (the validator declined) rather than risk a SystemStackError.
            matched = catch(Matcher::TOO_DEEP) { Matcher.new(schema).matches?(document, schema) }
            return :undefined if matched == Matcher::TOO_DEEP

            [matched, matched ? [] : [MATCH_ERROR]]
          end

          # Resolve the document argument to a Ruby value, or an error. A string is JSON parsed (to any
          # value); a raw object or array is used directly; a raw scalar (number/boolean/null) is rejected,
          # matching gojsonschema's document loader.
          # @return [Array(Object?, Symbol?)]
          def self.load_document(value)
            case value
            when StringValue then parse_document_string(value.value)
            when ObjectValue, ArrayValue then [value.to_ruby, nil]
            else [nil, :error]
            end
          end
          private_class_method :load_document

          # A document passed as a JSON string: any well-formed JSON value, with the same encoding and
          # structural-comment guards as a schema string (Go's encoding/json rejects // and /* */ comments).
          def self.parse_document_string(string)
            return [nil, :error] unless usable_json_encoding?(string)
            return [nil, :error] if contains_json_comment?(string)

            [JSON.parse(string), nil]
          rescue JSON::ParserError
            [nil, :error]
          end
          private_class_method :parse_document_string

          # A pure-boolean document validator. Holds the root schema for `$ref` resolution and a per-ref
          # `visited` set keyed by [ref, document object id] so a self-referential schema validating a
          # non-shrinking document terminates instead of looping.
          # rubocop:disable Metrics/ClassLength
          class Matcher
            # Validation recurses through `matches?` (document drill-down, $ref-following, allOf/anyOf
            # nesting) and `canonical` (enum/const/uniqueItems equality). Both are bounded here so a
            # pathologically deep document or schema returns undefined instead of a SystemStackError that
            # would abort the whole policy (only BuiltinArgumentError is rescued by the registry). The bound
            # matches JSON.parse's default max_nesting (100) already enforced on the string-document path,
            # keeping the raw-input and string-input paths consistent. gojsonschema validates deeper (to
            # roughly 6000) before it too stack-overflows; documents nested past this bound are a documented
            # divergence (undefined vs OPA's true/false) rather than a crash in either tool.
            MAX_DEPTH = 100
            # Sentinel thrown past the recursion and caught at the `match` entry point.
            TOO_DEEP = :__match_schema_too_deep__

            def initialize(root)
              @root = root
              @visited = {}
              @depth = 0
            end

            # Bound one level of recursion; throw TOO_DEEP past the whole walk when the limit is exceeded.
            def with_depth
              @depth += 1
              throw TOO_DEEP, TOO_DEEP if @depth > MAX_DEPTH

              yield
            ensure
              @depth -= 1
            end

            # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
            # Whether `document` validates against `schema` (a subschema of the root). Applies every keyword
            # gojsonschema knows; the document matches only when all applicable keywords are satisfied.
            # :reek:TooManyStatements
            def matches?(document, schema)
              return schema unless schema.is_a?(Hash) # a boolean schema matches all (true) / nothing (false)

              with_depth do
                ref = schema["$ref"]
                next ref_matches?(document, schema, ref) if ref.is_a?(String)

                type_ok?(document, schema["type"]) &&
                  enum_ok?(document, schema) && const_ok?(document, schema) &&
                  number_ok?(document, schema) && string_ok?(document, schema) &&
                  array_ok?(document, schema) && object_ok?(document, schema) &&
                  logic_ok?(document, schema)
              end
            end
            # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

            private

            # Resolve a `$ref` against the root and validate the document against the target, guarding against
            # a non-terminating self-reference on the same document node.
            # :reek:NilCheck :reek:TooManyStatements
            def ref_matches?(document, _schema, ref)
              target = JsonSchema.resolve_ref_target(ref, @root)
              return true if target.nil?

              key = [ref, document.object_id]
              return true if @visited[key]

              @visited[key] = true
              result = matches?(document, target)
              @visited.delete(key)
              result
            end

            # `type` is a single name or an array of names; the document must be one of them. An empty array
            # imposes no constraint (gojsonschema matches anything). JSON's integer type also accepts an
            # integral float (5.0), matching gojsonschema.
            # :reek:NilCheck
            def type_ok?(document, type)
              return true if type.nil?

              names = type.is_a?(Array) ? type : [type]
              names.empty? || names.any? { |name| json_type?(document, name) }
            end

            # rubocop:disable Metrics/CyclomaticComplexity
            # :reek:TooManyStatements :reek:ControlParameter :reek:NilCheck
            def json_type?(document, name)
              case name
              when "null" then document.nil?
              when "boolean" then [true, false].include?(document)
              when "object" then document.is_a?(Hash)
              when "array" then document.is_a?(Array)
              when "string" then document.is_a?(String)
              when "number" then numeric_doc?(document)
              when "integer" then integer_doc?(document)
              else false
              end
            end
            # rubocop:enable Metrics/CyclomaticComplexity

            # A JSON number (Integer/Float), excluding Ruby booleans (not Numeric anyway).
            def numeric_doc?(document)
              document.is_a?(Numeric)
            end

            # An integer, or a float with no fractional part (gojsonschema treats 5.0 as an integer).
            def integer_doc?(document)
              return true if document.is_a?(Integer)

              document.is_a?(Float) && document.finite? && document == document.to_i
            end

            # An empty enum imposes no constraint (gojsonschema matches anything), unlike the JSON-Schema
            # standard where nothing would validate.
            # :reek:NilCheck
            def enum_ok?(document, schema)
              enum = schema["enum"]
              enum.nil? || enum.empty? || enum.any? { |value| json_equal?(document, value) }
            end

            # :reek:NilCheck
            def const_ok?(document, schema)
              return true unless schema.key?("const")

              json_equal?(document, schema["const"])
            end

            # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
            # Numeric keywords (only constrain numbers; a non-number document satisfies them vacuously).
            # :reek:TooManyStatements :reek:NilCheck
            def number_ok?(document, schema)
              return true unless numeric_doc?(document)

              minimum = schema["minimum"]
              maximum = schema["maximum"]
              return false if minimum && document < minimum
              return false if maximum && document > maximum
              return false unless exclusive_ok?(document, schema["exclusiveMinimum"], minimum, :>)
              return false unless exclusive_ok?(document, schema["exclusiveMaximum"], maximum, :<)
              return false if (multiple = schema["multipleOf"]) && !multiple_of?(document, multiple)

              true
            end
            # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

            # exclusiveMinimum/Maximum: a number bound (document strictly beyond it), or the draft-04 boolean
            # form (true → the paired minimum/maximum becomes strict). `comparison` is :> for the lower bound.
            # :reek:ControlParameter :reek:LongParameterList :reek:NilCheck
            def exclusive_ok?(document, bound, paired, comparison)
              return true if bound.nil?
              return document.public_send(comparison, bound) if numeric_doc?(bound)
              return true unless bound == true && numeric_doc?(paired)

              document.public_send(comparison, paired)
            end

            # multipleOf: the quotient must be an integer. gojsonschema uses arbitrary-precision decimal
            # arithmetic (big.Rat), so this does too — a Float division would overflow to Infinity for a huge
            # document over a tiny divisor, and Infinity.round raises FloatDomainError (a non-total crash that
            # would abort the whole policy). Building each Rational from the number's decimal text keeps 0.3
            # as 3/10 (matching gojsonschema's parse of the JSON token) rather than the binary 0.2999… that
            # Float#to_r yields, and is exact at any magnitude.
            def multiple_of?(document, divisor)
              return false unless finite_number?(document) && finite_number?(divisor)

              (decimal_rational(document) / decimal_rational(divisor)).denominator == 1
            end

            # A non-finite Float (Infinity/NaN — reachable as `1e400` overflows JSON.parse to Infinity, or
            # from Rego arithmetic) has no decimal text Rational() accepts, so it would raise ArgumentError
            # and abort the policy. Guard it out; the gem's Float model already collapses such magnitudes to
            # Infinity (a documented number-model divergence from OPA's arbitrary-precision decimals), so the
            # boolean here is best-effort while staying total.
            def finite_number?(number)
              !number.is_a?(Float) || number.finite?
            end

            # A Rational from the number's shortest decimal representation (the JSON token it round-trips to).
            def decimal_rational(number)
              Rational(number.to_s)
            end

            # String keywords (length is by characters; pattern is an unanchored RE2 match).
            # rubocop:disable Metrics/CyclomaticComplexity
            # :reek:TooManyStatements :reek:NilCheck
            def string_ok?(document, schema)
              return true unless document.is_a?(String)

              length = document.length
              return false if (min = schema["minLength"]) && length < min
              return false if (max = schema["maxLength"]) && length > max
              return false if (pattern = schema["pattern"]) && !JsonSchema.re2_match?(pattern, document)

              true
            end
            # rubocop:enable Metrics/CyclomaticComplexity

            # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
            # Array keywords (only constrain arrays).
            # :reek:TooManyStatements :reek:NilCheck
            def array_ok?(document, schema)
              return true unless document.is_a?(Array)

              size = document.length
              return false if (min = schema["minItems"]) && size < min
              return false if (max = schema["maxItems"]) && size > max
              return false if schema["uniqueItems"] == true && !unique?(document)
              return false unless items_ok?(document, schema)
              return false unless contains_ok?(document, schema)

              true
            end
            # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

            def unique?(document)
              document.uniq { |item| canonical(item) }.length == document.length
            end

            # `items` as a single schema (every element) or a tuple (positional), with `additionalItems`
            # governing elements past the tuple.
            # :reek:NilCheck :reek:TooManyStatements
            def items_ok?(document, schema)
              items = schema["items"]
              return true if items.nil?
              return document.all? { |element| matches?(element, items) } unless items.is_a?(Array)
              # gojsonschema only wires additionalItems inside a non-empty tuple, so an empty `items` array
              # leaves every element unconstrained (additionalItems is ignored), unlike the standard.
              return true if items.empty?

              tuple_ok?(document, items, schema["additionalItems"])
            end

            # :reek:NilCheck
            def tuple_ok?(document, tuple, additional)
              document.each_with_index.all? do |element, index|
                schema = tuple[index]
                schema.nil? ? additional_schema_ok?(element, additional) : matches?(element, schema)
              end
            end

            # An `additionalItems` / `additionalProperties` value is a boolean (true permits, false forbids)
            # or a subschema the element must match.
            # :reek:NilCheck
            def additional_schema_ok?(value, additional)
              return true if additional.nil? || additional == true
              return false if additional == false

              matches?(value, additional)
            end

            # :reek:NilCheck
            def contains_ok?(document, schema)
              contains = schema["contains"]
              contains.nil? || document.any? { |element| matches?(element, contains) }
            end

            # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
            # Object keywords (only constrain objects). Keys are stringified up front: OPA marshals the
            # document to JSON before gojsonschema sees it, so a Rego object with non-string keys (1, true)
            # validates as if the keys were "1" / "true" against required/properties/patternProperties/etc.
            # Nested objects are stringified as `matches?` recurses back into object_ok?.
            # :reek:TooManyStatements :reek:NilCheck
            def object_ok?(document, schema)
              return true unless document.is_a?(Hash)

              object = string_keyed(document)
              size = object.size
              return false if (min = schema["minProperties"]) && size < min
              return false if (max = schema["maxProperties"]) && size > max
              return false unless required_ok?(object, schema["required"])
              return false unless properties_ok?(object, schema)
              return false unless dependencies_ok?(object, schema)
              return false unless property_names_ok?(object, schema)

              true
            end
            # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

            # The object with its immediate keys stringified (idempotent for the usual all-string-keyed JSON
            # object, so no allocation in the common case).
            def string_keyed(object)
              return object if object.keys.all?(String)

              object.transform_keys(&:to_s)
            end

            # :reek:NilCheck
            def required_ok?(document, required)
              required.nil? || required.all? { |name| document.key?(name) }
            end

            # `properties` / `patternProperties` validate matching members; `additionalProperties` governs
            # members matched by neither.
            # :reek:TooManyStatements :reek:NilCheck
            def properties_ok?(document, schema)
              properties = schema["properties"] || {}
              pattern_properties = schema["patternProperties"] || {}
              additional = schema["additionalProperties"]

              document.all? do |name, value|
                property_value_ok?(name, value, properties, pattern_properties, additional)
              end
            end

            # rubocop:disable Metrics/MethodLength
            # :reek:LongParameterList :reek:TooManyStatements :reek:NilCheck
            def property_value_ok?(name, value, properties, pattern_properties, additional)
              matched = false
              if properties.key?(name)
                matched = true
                return false unless matches?(value, properties[name])
              end
              pattern_properties.each do |pattern, subschema|
                next unless JsonSchema.re2_match?(pattern, name)

                matched = true
                return false unless matches?(value, subschema)
              end
              additional_property_ok?(value, additional, matched)
            end
            # rubocop:enable Metrics/MethodLength

            # :reek:ControlParameter
            def additional_property_ok?(value, additional, matched)
              matched || additional_schema_ok?(value, additional)
            end

            # `dependencies`: a schema dependency (the object must match it when the key is present) or a
            # property dependency (those keys must also be present).
            # :reek:NilCheck
            def dependencies_ok?(document, schema)
              dependencies = schema["dependencies"]
              return true if dependencies.nil?

              dependencies.all? do |name, dependency|
                !document.key?(name) || dependency_ok?(document, dependency)
              end
            end

            def dependency_ok?(document, dependency)
              return dependency.all? { |name| document.key?(name) } if dependency.is_a?(Array)

              matches?(document, dependency)
            end

            # :reek:NilCheck
            def property_names_ok?(document, schema)
              names = schema["propertyNames"]
              names.nil? || document.each_key.all? { |name| matches?(name, names) }
            end

            # The applicator keywords: allOf/anyOf/oneOf/not and if/then/else.
            def logic_ok?(document, schema)
              all_of_ok?(document, schema) && any_of_ok?(document, schema) &&
                one_of_ok?(document, schema) && not_ok?(document, schema) &&
                conditional_ok?(document, schema)
            end

            # :reek:NilCheck
            def all_of_ok?(document, schema)
              subschemas = schema["allOf"]
              subschemas.nil? || subschemas.all? { |subschema| matches?(document, subschema) }
            end

            # An empty anyOf/oneOf imposes no constraint in gojsonschema (like empty enum/type), where the
            # standard `[].any?`/`[].one?` would be false. allOf needs no such guard (`[].all?` is already true).
            # :reek:NilCheck
            def any_of_ok?(document, schema)
              subschemas = schema["anyOf"]
              subschemas.nil? || subschemas.empty? || subschemas.any? { |subschema| matches?(document, subschema) }
            end

            # :reek:NilCheck
            def one_of_ok?(document, schema)
              subschemas = schema["oneOf"]
              subschemas.nil? || subschemas.empty? || subschemas.one? { |subschema| matches?(document, subschema) }
            end

            # :reek:NilCheck
            def not_ok?(document, schema)
              subschema = schema["not"]
              subschema.nil? || !matches?(document, subschema)
            end

            # `if`/`then`/`else`: if the document matches `if`, it must match `then`; otherwise `else`.
            # :reek:NilCheck
            def conditional_ok?(document, schema)
              condition = schema["if"]
              return true if condition.nil?

              branch = matches?(document, condition) ? schema["then"] : schema["else"]
              branch.nil? || matches?(document, branch)
            end

            # JSON value equality (numbers compare by value, objects/arrays structurally).
            def json_equal?(left, right)
              canonical(left) == canonical(right)
            end

            # A comparable, type-aware form: numbers as Float (so 1 == 1.0), composites recursed. Bounded by
            # the same depth guard as `matches?` (enum/const/uniqueItems can compare arbitrarily deep values).
            # Object keys are stringified, matching OPA, which marshals the document to JSON before
            # gojsonschema sees it (so a 1 / true / "1" key all compare as "1" / "true"); stringifying also
            # keeps the entry sort total for heterogeneous Rego keys instead of raising on `1 <=> "b"`.
            # :reek:TooManyStatements
            def canonical(value)
              case value
              when Integer, Float then [:number, value.to_f]
              when Array then with_depth { [:array, value.map { |element| canonical(element) }] }
              when Hash then with_depth { [:object, canonical_entries(value)] }
              else [:scalar, value]
              end
            end

            # Object entries as [stringified key, canonical value], sorted into a deterministic order by a
            # fully string comparison (key first, then the value's serialization) so no `<=>` ever touches
            # mutually-incomparable Rego scalars.
            def canonical_entries(object)
              object.map { |key, member| [key.to_s, canonical(member)] }
                    .sort_by { |key, member| [key, member.to_s] }
            end
          end
          # rubocop:enable Metrics/ClassLength
        end
      end
    end
  end
end
