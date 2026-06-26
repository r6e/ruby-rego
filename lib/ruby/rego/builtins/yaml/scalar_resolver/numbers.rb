# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Yaml
        # Plain-scalar number resolution (yaml.v2 resolveTable + Go strconv parsing).
        # Lives apart from the resolution core so the main file stays under RubyCritic's
        # complexity budget. Constants (RESOLVE_MAP, FLOAT_RE, ...) live in the main module
        # body and resolve here via lexical scope, since this file loads after it.
        module ScalarResolver
          # @return [Integer, Float, nil]
          def self.numeric(string)
            plain = string.delete("_")
            integer = parse_integer(plain)
            return integer if integer
            return nil unless FLOAT_RE.match?(plain)

            float = float_value(plain)
            # An overflow to ±Inf is not a number in go-yaml — it falls back to its string
            # text (1e999 -> "1e999"). An underflow is a finite 0.0 and stays the number 0.
            # (The !!float tag path in tags.rb calls json_number directly, so it still
            # undefines an overflow, as OPA does.)
            return nil unless float&.finite?

            json_number(float)
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
            # A non-finite float passes through unchanged so reject_non_finite (run from
            # load) raises ResolveError -> undefined. Only `numeric` (the plain-scalar path)
            # maps non-finite to nil for a string fallback; the !!float tag path (tags.rb)
            # routes here and MUST keep this passthrough so `!!float 1e999` stays undefined.
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
        end
      end
    end
  end
end
