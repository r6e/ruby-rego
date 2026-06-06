# frozen_string_literal: true

# rubocop:disable Metrics/ModuleLength

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
          # Raised when a parsed document cannot be represented as JSON (Inf/NaN).
          class ResolveError < StandardError; end

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

            float = Float(plain, exception: false)
            float && json_number(float)
          end
          private_class_method :numeric

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
            document = Psych.parse_stream(string).children.first
            return nil unless document

            value = build(document.root, {})
            reject_non_finite(value)
            value
          end

          # @return [Object]
          def self.build(node, anchors)
            case node
            when Psych::Nodes::Scalar then anchored(node, anchors) { node.plain ? resolve(node.value) : node.value }
            when Psych::Nodes::Sequence then anchored(node, anchors) { node.children.map { |child| build(child, anchors) } }
            when Psych::Nodes::Mapping then build_mapping(node, anchors)
            when Psych::Nodes::Alias then anchors.fetch(node.anchor)
            else raise ResolveError, "unsupported node #{node.class}"
            end
          end
          private_class_method :build

          # Registers a built value under its anchor (if any) so later aliases resolve.
          def self.anchored(node, anchors)
            value = yield
            anchor = node.anchor
            anchors[anchor] = value if anchor && !anchor.empty?
            value
          end
          private_class_method :anchored

          # :reek:TooManyStatements
          def self.build_mapping(node, anchors)
            result = {} # @type var result: Hash[String, untyped]
            anchored(node, anchors) { result }
            node.children.each_slice(2) do |key_node, value_node|
              key = build(key_node, anchors)
              built = build(value_node, anchors)
              next merge_into(result, built) if key == "<<"

              result[json_key(key)] = built
            end
            result
          end
          private_class_method :build_mapping

          # YAML merge key (`<<`): fill in entries not already present.
          def self.merge_into(result, source)
            sources = source.is_a?(Array) ? source : [source]
            sources.each do |entry|
              entry.each { |key, value| result[key] = value unless result.key?(key) } if entry.is_a?(Hash)
            end
          end
          private_class_method :merge_into

          # JSON object keys are strings; coerce a resolved key the way OPA's round-trip does.
          # @return [String]
          def self.json_key(key)
            case key
            when String then key
            when nil then "null"
            when true then "true"
            when false then "false"
            when Float then Emitter.float_string(key)
            else key.to_s
            end
          end
          private_class_method :json_key

          # JSON cannot represent Inf/NaN; OPA returns undefined for such documents.
          def self.reject_non_finite(value)
            case value
            when Float then raise ResolveError, "non-finite number" unless value.finite?
            when Array then value.each { |item| reject_non_finite(item) }
            when Hash then value.each_value { |item| reject_non_finite(item) }
            end
          end
          private_class_method :reject_non_finite
        end
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength
