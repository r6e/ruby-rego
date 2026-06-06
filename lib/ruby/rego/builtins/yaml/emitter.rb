# frozen_string_literal: true

# rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/ModuleLength

require "psych"

module Ruby
  module Rego
    module Builtins
      module Yaml
        # Builds a Psych node tree and emits it, matching OPA's yaml.marshal byte-for-byte.
        #
        # Layout, folding, escaping, and the plain→single/double downgrade are delegated
        # to Psych (libyaml — the engine gopkg.in/yaml.v2 ports), so they match for free.
        # This module supplies only what diverges from Psych's defaults: object keys are
        # sorted, floats use Go's strconv 'g' (shortest, eprec=6) formatting, nil emits as
        # `null`, and scalar styles are set explicitly (DOUBLE for type-ambiguous strings).
        module Emitter
          # Raised when a value cannot be marshaled (e.g. a non-finite number).
          class MarshalError < StandardError; end

          PLAIN = Psych::Nodes::Scalar::PLAIN
          DOUBLE = Psych::Nodes::Scalar::DOUBLE_QUOTED
          LITERAL = Psych::Nodes::Scalar::LITERAL
          # ANY lets libyaml auto-pick plain/single/double exactly as yaml.v2's libyaml
          # does — so the structural quote choice matches OPA for free.
          AUTO = Psych::Nodes::Scalar::ANY
          BLOCK_SEQ = Psych::Nodes::Sequence::BLOCK
          BLOCK_MAP = Psych::Nodes::Mapping::BLOCK

          # yaml.v2 quotes strings that would otherwise resolve to a timestamp or a
          # base-60 number (the latter dropped from resolution but still quoted out).
          TIMESTAMP = /\A\d{4}-\d{1,2}-\d{1,2}([Tt ]\d{1,2}:\d{1,2}:\d{1,2}(\.\d+)?([Zz]|[+-]\d{1,2}(:\d{2})?)?)?\z/
          BASE60 = /\A[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9_]*)?\z/

          # @param ruby [Object] a JSON-compatible Ruby value
          # @return [String]
          def self.emit(ruby)
            document = Psych::Nodes::Document.new([], [], true)
            document.implicit_end = true
            document.children << build_node(ruby)
            stream = Psych::Nodes::Stream.new
            stream.children << document
            stream.to_yaml
          end

          # @return [Psych::Nodes::Node]
          # :reek:TooManyStatements
          def self.build_node(ruby)
            case ruby
            when nil then scalar("null", PLAIN)
            when true then scalar("true", PLAIN)
            when false then scalar("false", PLAIN)
            when Integer then scalar(ruby.to_s, PLAIN)
            when Float then scalar(float_string(ruby), PLAIN)
            when String then scalar(ruby, string_style(ruby))
            when Symbol then scalar(ruby.to_s, string_style(ruby.to_s))
            when Array then sequence(ruby)
            when Set then sequence(ruby.to_a)
            when Hash then mapping(ruby)
            else raise MarshalError, "unsupported type #{ruby.class}"
            end
          end
          private_class_method :build_node

          # Builds a scalar node. PLAIN/DOUBLE force that style; AUTO sets both implicit
          # flags so libyaml picks plain/single/double/literal itself (no `!` tag).
          # @return [Psych::Nodes::Scalar]
          def self.scalar(value, style)
            case style
            when PLAIN then Psych::Nodes::Scalar.new(value, nil, nil, true, false, PLAIN)
            when DOUBLE then Psych::Nodes::Scalar.new(value, nil, nil, false, true, DOUBLE)
            when LITERAL then Psych::Nodes::Scalar.new(value, nil, nil, false, true, LITERAL)
            else Psych::Nodes::Scalar.new(value, nil, nil, true, true, AUTO)
            end
          end
          private_class_method :scalar

          # Force DOUBLE only where yaml.v2 must quote to preserve a string: empty, or a
          # value that would resolve to a non-string / timestamp / base-60. Otherwise AUTO
          # lets libyaml make the same plain/single/double/literal choice OPA does.
          # @return [Integer]
          def self.string_style(string)
            return DOUBLE if string.empty? || ScalarResolver.ambiguous?(string)
            return DOUBLE if TIMESTAMP.match?(string) || BASE60.match?(string)
            return LITERAL if string.include?("\n")

            AUTO
          end
          private_class_method :string_style

          # @return [Psych::Nodes::Sequence]
          def self.sequence(array)
            node = Psych::Nodes::Sequence.new(nil, nil, true, BLOCK_SEQ)
            array.each { |item| node.children << build_node(item) }
            node
          end
          private_class_method :sequence

          # OPA marshals via JSON: object keys are stringified, then sorted. A non-string
          # Rego key (number/bool/null) is a valid object key, so build each value from
          # its own entry rather than re-fetching by the stringified key.
          # @return [Psych::Nodes::Mapping]
          def self.mapping(hash)
            node = Psych::Nodes::Mapping.new(nil, nil, true, BLOCK_MAP)
            hash.map { |key, value| [key_string(key), value] }.sort_by(&:first).each do |key, value|
              node.children << scalar(key, string_style(key))
              node.children << build_node(value)
            end
            node
          end
          private_class_method :mapping

          # The string form of an object key (mirrors how OPA stringifies map keys).
          # @return [String]
          def self.key_string(key)
            case key
            when String then key
            when Float then float_string(key)
            when true then "true"
            when false then "false"
            when nil then "null"
            else key.to_s
            end
          end
          private_class_method :key_string

          # Go strconv.FormatFloat(f, 'g', -1, 64): shortest digits, scientific when the
          # decimal exponent is < -4 or >= the precision (6 for shortest 'g').
          # @return [String]
          def self.float_string(float)
            raise MarshalError, "non-finite number" unless float.finite?
            return float.to_s.start_with?("-") ? "-0" : "0" if float.zero?

            digits, point = shortest_digits(float.abs)
            exponent = point - 1
            body = exponent < -4 || exponent >= 6 ? scientific(digits, exponent) : fixed(digits, point)
            float.negative? ? "-#{body}" : body
          end

          # Extracts the shortest significant digits and the decimal-point position such
          # that value == 0.<digits> * 10**point. Ruby's Float#to_s gives shortest digits.
          # @return [Array(String, Integer)]
          # :reek:TooManyStatements
          def self.shortest_digits(float)
            mantissa, exponent = float.to_s.split(/e/i)
            integer_part, fraction = mantissa.to_s.split(".")
            integer_part = integer_part.to_s
            combined = integer_part + fraction.to_s
            without_leading = combined.sub(/\A0+/, "")
            point = integer_part.length + (exponent || "0").to_i - (combined.length - without_leading.length)
            digits = without_leading.sub(/0+\z/, "")
            digits.empty? ? ["0", 1] : [digits, point]
          end
          private_class_method :shortest_digits

          # @return [String]
          def self.fixed(digits, point)
            return "0.#{"0" * -point}#{digits}" if point <= 0
            return digits + ("0" * (point - digits.length)) if point >= digits.length

            "#{digits[0...point]}.#{digits[point..]}"
          end
          private_class_method :fixed

          # @return [String]
          def self.scientific(digits, exponent)
            mantissa = digits.length == 1 ? digits : "#{digits[0]}.#{digits[1..]}"
            "#{mantissa}e#{exponent.negative? ? "-" : "+"}#{format("%02d", exponent.abs)}"
          end
          private_class_method :scientific
        end
      end
    end
  end
end
# rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/ModuleLength
