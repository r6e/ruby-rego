# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Yaml
        # Go strconv 'g' float formatting (FormatFloat(f, 'g', -1, 64)): shortest digits
        # with scientific notation when the decimal exponent is < -4 or >= 6. Lives apart
        # from the node-building core so the emitter file stays under RubyCritic's
        # complexity budget; float_string stays public because ScalarResolver calls it.
        module Emitter
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
          # rubocop:disable Metrics/AbcSize
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
          # rubocop:enable Metrics/AbcSize

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
