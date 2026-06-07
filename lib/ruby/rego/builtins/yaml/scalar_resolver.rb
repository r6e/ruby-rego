# frozen_string_literal: true

# rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/ModuleLength

require "psych"

module Ruby
  module Rego
    module Builtins
      module Yaml
        # Resolves plain YAML scalars the way gopkg.in/yaml.v2 (v2.4.0) does, and walks
        # a parsed document into JSON-compatible Ruby values — the combination OPA gets
        # from sigs.k8s.io/yaml's YAML→JSON conversion. Notably: timestamps are NOT
        # resolved (they stay strings, matching OPA's JSON round-trip), object keys are
        # stringified, and a non-finite number makes the whole result undefined.
        module ScalarResolver
          # Raised when a document cannot be represented as JSON (Inf/NaN), is invalid
          # (undefined alias, bad merge), or breaches a DoS bound. The caller maps it to
          # undefined / false, matching OPA.
          class ResolveError < StandardError; end

          # DoS bounds. OPA relies on Go runtime limits absent here, so an untrusted
          # document exceeding these yields undefined rather than exhausting memory/stack:
          # source byte length, nesting depth (guards a Ruby stack overflow), and total
          # expanded nodes (guards against alias-expansion "billion laughs" bombs).
          MAX_YAML_SOURCE = 1_000_000
          MAX_DEPTH = 1_000
          MAX_NODES = 5_000_000

          # Plain scalars with a fixed meaning (yaml.v2 resolveMap).
          RESOLVE_MAP = {
            "" => nil, "~" => nil, "null" => nil, "Null" => nil, "NULL" => nil,
            "y" => true, "Y" => true, "yes" => true, "Yes" => true, "YES" => true,
            "true" => true, "True" => true, "TRUE" => true, "on" => true, "On" => true, "ON" => true,
            "n" => false, "N" => false, "no" => false, "No" => false, "NO" => false,
            "false" => false, "False" => false, "FALSE" => false, "off" => false, "Off" => false, "OFF" => false,
            ".nan" => Float::NAN, ".NaN" => Float::NAN, ".NAN" => Float::NAN,
            ".inf" => Float::INFINITY, ".Inf" => Float::INFINITY, ".INF" => Float::INFINITY,
            "+.inf" => Float::INFINITY, "+.Inf" => Float::INFINITY, "+.INF" => Float::INFINITY,
            "-.inf" => -Float::INFINITY, "-.Inf" => -Float::INFINITY, "-.INF" => -Float::INFINITY
          }.freeze

          # Prefix of an explicit core YAML schema tag (e.g. "tag:yaml.org,2002:int").
          TAG_PREFIX = "tag:yaml.org,2002:"

          # First-byte hints that a scalar might be a number (yaml.v2 resolveTable).
          NUMBER_LEADS = "+-.0123456789"
          FLOAT_RE = /\A[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?\z/

          # Resolves a plain scalar string to its Ruby value (or itself, as a string).
          # @return [Object]
          def self.resolve(string)
            return RESOLVE_MAP[string] if RESOLVE_MAP.key?(string)
            return string if string.empty? || !NUMBER_LEADS.include?(string[0].to_s)

            numeric(string) || string
          end

          # True when a plain scalar would resolve to something other than a string
          # (so the emitter must quote it).
          # @return [bool]
          def self.ambiguous?(string)
            resolved = resolve(string)
            !(resolved.is_a?(String) && resolved == string)
          end

          # @return [Integer, Float, nil]
          def self.numeric(string)
            plain = string.delete("_")
            integer = parse_integer(plain)
            return integer if integer
            return nil unless FLOAT_RE.match?(plain)

            float = float_value(plain)
            float && json_number(float)
          end
          private_class_method :numeric

          # Parses a FLOAT_RE-matched scalar. Dot-edge forms (".5", "5.", "5.e3") are
          # normalized to have a digit on both sides of the point so Ruby's Float accepts
          # them on every supported version — Ruby < 3.4 rejects a bare leading/trailing
          # dot, unlike Go's strconv (which OPA uses).
          # @return [Float, nil]
          def self.float_value(plain)
            normalized = plain.sub(/\A(?<sign>[+-]?)\./, '\k<sign>0.').sub(/\.(?=[eE]|\z)/, ".0")
            Float(normalized, exception: false)
          end
          private_class_method :float_value

          # OPA's YAML→JSON round-trip renders an integer-valued float without a decimal
          # (Go json uses fixed notation for 1e-6 <= |x| < 1e21), so it reparses as an
          # integer. Mirror that so e.g. "1.0"/"1e10" unmarshal to integers, not floats.
          # @return [Integer, Float]
          def self.json_number(float)
            return float unless float.finite?
            return 0 if float.zero?
            return float.to_i if float == float.to_i && float.abs >= 1e-6 && float.abs < 1e21

            float
          end
          private_class_method :json_number

          # Go strconv.ParseInt base 0: 0x hex, 0o/leading-zero octal, 0b binary, decimal.
          # @return [Integer, nil]
          def self.parse_integer(string)
            sign, digits = split_sign(string)
            base, body = integer_base(digits)
            return nil if body.empty?

            value = Integer(body, base, exception: false)
            value && (sign * value)
          end
          private_class_method :parse_integer

          # @return [Array(Integer, String)]
          def self.split_sign(string)
            return [-1, string[1..] || ""] if string.start_with?("-")
            return [1, string[1..] || ""] if string.start_with?("+")

            [1, string]
          end
          private_class_method :split_sign

          # @return [Array(Integer, String)]
          def self.integer_base(digits)
            case digits
            when /\A0[xX][0-9a-fA-F]+\z/ then [16, digits[2..].to_s]
            when /\A0[oO][0-7]+\z/ then [8, digits[2..].to_s]
            when /\A0[bB][01]+\z/ then [2, digits[2..].to_s]
            when /\A0[0-7]+\z/ then [8, digits[1..].to_s]
            else [10, digits]
            end
          end
          private_class_method :integer_base

          # Parses YAML and returns the first document as JSON-compatible Ruby values.
          # @return [Object]
          def self.load(string)
            raise ResolveError, "yaml too long" if string.bytesize > MAX_YAML_SOURCE

            document = Psych.parse_stream(string).children.first
            # An absent document or one with no root node is an empty document, which
            # decodes to null (matching yaml.v2 / sigs.k8s.io/yaml), not an error.
            return nil if document.nil? || document.root.nil?

            value = build(document.root, {}, 0)
            reject_non_finite(value, [MAX_NODES], 0)
            value
          end

          # @return [Object]
          # :reek:TooManyStatements
          def self.build(node, anchors, depth)
            raise ResolveError, "yaml nested too deep" if depth > MAX_DEPTH

            case node
            when Psych::Nodes::Scalar then anchored(node, anchors) { scalar_value(node) }
            when Psych::Nodes::Sequence
              anchored(node, anchors) { node.children.map { |child| build(child, anchors, depth + 1) } }
            when Psych::Nodes::Mapping then build_mapping(node, anchors, depth)
            when Psych::Nodes::Alias then anchors.fetch(node.anchor) { raise ResolveError, "undefined alias #{node.anchor}" }
            else raise ResolveError, "unsupported node #{node.class}"
            end
          end
          private_class_method :build

          # Resolves a scalar node's value. An explicit core tag (!!str/!!int/!!float/!!bool/
          # !!null) coerces the value to that type (erroring on a value that can't be coerced,
          # like OPA); otherwise a plain scalar is resolved and a quoted one is a string.
          # @return [Object]
          def self.scalar_value(node)
            tag = node.tag
            return tag_coerce(tag[TAG_PREFIX.length..], node.value) if tag&.start_with?(TAG_PREFIX)

            node.plain ? resolve(node.value) : node.value
          end
          private_class_method :scalar_value

          # @return [Object]
          def self.tag_coerce(type, value)
            case type
            when "int" then tag_int(value)
            when "float" then tag_float(value)
            when "bool" then tag_bool(value)
            when "null" then tag_null(value)
            when "binary" then tag_binary(value)
            # !!str — and any unrecognized core tag (e.g. !!timestamp) — yields the raw string.
            else value
            end
          end
          private_class_method :tag_coerce

          # @return [Integer]
          def self.tag_int(value)
            parse_integer(value.delete("_")) || raise(ResolveError, "invalid !!int")
          end
          private_class_method :tag_int

          # @return [Float, Integer]
          def self.tag_float(value)
            mapped = RESOLVE_MAP[value]
            return mapped if mapped.is_a?(Float) # .inf / .nan

            plain = value.delete("_")
            raise ResolveError, "invalid !!float" unless FLOAT_RE.match?(plain)

            json_number(float_value(plain) || raise(ResolveError, "invalid !!float"))
          end
          private_class_method :tag_float

          # base64 (yaml.v2 emits it wrapped, so whitespace is stripped). A pathologically
          # malformed payload yields undefined; OPA's leniency for some non-base64 bytes is
          # an unreproduced edge.
          # @return [String]
          def self.tag_binary(value)
            value.gsub(/\s/, "").unpack1("m0")
          rescue ArgumentError
            raise ResolveError, "invalid !!binary"
          end
          private_class_method :tag_binary

          # @return [bool]
          def self.tag_bool(value)
            mapped = RESOLVE_MAP[value]
            return mapped if [true, false].include?(mapped)

            raise ResolveError, "invalid !!bool"
          end
          private_class_method :tag_bool

          # @return [nil]
          def self.tag_null(value)
            return nil if RESOLVE_MAP.key?(value) && RESOLVE_MAP[value].nil?

            raise ResolveError, "invalid !!null"
          end
          private_class_method :tag_null

          # Registers a built value under its anchor (if any) so later aliases resolve.
          def self.anchored(node, anchors)
            value = yield
            anchor = node.anchor
            anchors[anchor] = value if anchor && !anchor.empty?
            value
          end
          private_class_method :anchored

          # :reek:TooManyStatements
          def self.build_mapping(node, anchors, depth)
            result = {} # @type var result: Hash[String, untyped]
            anchored(node, anchors) { result }
            node.children.each_slice(2) do |key_node, value_node|
              key = build(key_node, anchors, depth + 1)
              built = build(value_node, anchors, depth + 1)
              next merge_into(result, built) if merge_key?(key, key_node)

              result[json_key(key)] = built
            end
            result
          end
          private_class_method :build_mapping

          # A `<<` merge key applies only when written as a plain scalar (a quoted
          # "<<" is an ordinary string key, matching yaml.v2's isMerge).
          def self.merge_key?(key, key_node)
            key == "<<" && key_node.is_a?(Psych::Nodes::Scalar) && key_node.plain
          end
          private_class_method :merge_key?

          # YAML merge key (`<<`): fill in entries not already present. A non-mapping
          # merge source is invalid (yaml.v2 errors), so it yields undefined.
          def self.merge_into(result, source)
            sources = source.is_a?(Array) ? source : [source]
            sources.each do |entry|
              raise ResolveError, "merge source is not a mapping" unless entry.is_a?(Hash)

              entry.each { |key, value| result[key] = value unless result.key?(key) }
            end
          end
          private_class_method :merge_into

          # JSON object keys are strings: resolve the key and stringify it (so 0x1F => "31",
          # 1.0 => "1", true => "true"). A non-finite float key normalizes to OPA's
          # canonical form. NOTE: a finite non-integer float key (e.g. 1.123456789) is
          # formatted with Ruby float64 shortest, whereas OPA uses Go float32 ('g', -1, 32),
          # so very-high-precision float map keys can differ — a rare, documented edge.
          # @return [String]
          def self.json_key(key)
            return canonical_float(key) if key.is_a?(Float) && !key.finite?

            case key
            when String then key
            when true then "true"
            when false then "false"
            when Integer then key.to_s
            when Float then Emitter.float_string(key)
            # A null or composite (array/object) key cannot be a JSON object key, so OPA's
            # round-trip rejects it; yield undefined to match.
            else raise ResolveError, "invalid object key #{key.class}"
            end
          end
          private_class_method :json_key

          # @return [String]
          def self.canonical_float(float)
            return ".nan" if float.nan?

            float.positive? ? ".inf" : "-.inf"
          end
          private_class_method :canonical_float

          # JSON cannot represent Inf/NaN (=> undefined). The budget caps total expansion
          # (alias bombs), and the depth cap stops cyclic anchors (e.g. `a: &a {b: *a}`)
          # before they overflow the stack — both surface as undefined.
          def self.reject_non_finite(value, budget, depth)
            budget[0] -= 1
            raise ResolveError, "yaml too large" if budget[0].negative?
            raise ResolveError, "yaml nested too deep" if depth > MAX_DEPTH

            case value
            when Float then raise ResolveError, "non-finite number" unless value.finite?
            when Array then value.each { |item| reject_non_finite(item, budget, depth + 1) }
            when Hash then value.each_value { |item| reject_non_finite(item, budget, depth + 1) }
            end
          end
          private_class_method :reject_non_finite
        end
      end
    end
  end
end
# rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/ModuleLength
