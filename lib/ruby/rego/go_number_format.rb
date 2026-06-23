# frozen_string_literal: true

module Ruby
  module Rego
    # Renders a number's shortest significant digits the way Go's strconv / math/big 'g' verb does
    # (the format OPA's FloatToNumber applies to a non-integer big.Float result): shortest digits, with
    # scientific notation when the decimal exponent is < -4 or >= 6, and an exponent that is always
    # signed and zero-padded to at least two digits (`1e-05`, `1.2345675e+06`). Integer-valued results
    # are formatted by the caller as a full decimal (Go's 'f' verb), so this module only renders the
    # fractional ('g') case.
    #
    # Both the arbitrary-precision Number (flt-sourced digits) and the YAML emitter (Ruby Float#to_s
    # digits) share this single Go-faithful renderer.
    module GoNumberFormat
      # Render shortest digits + decimal-point position as Go's 'g' verb would.
      #
      # @param digits [String] shortest significant digits, no leading/trailing zeros
      # @param point [Integer] decimal-point position such that value == 0.<digits> * 10**point
      # @param negative [Boolean] whether the value is negative
      # @return [String]
      def self.render(digits, point, negative)
        exponent = point - 1
        body = exponent < -4 || exponent >= 6 ? scientific(digits, exponent) : fixed(digits, point)
        negative ? "-#{body}" : body
      end

      # Parse a shortest-form numeric string (Ruby Float#to_s or flt's free format, decimal or
      # scientific, case-insensitive `e`) into [digits, point] such that the magnitude equals
      # 0.<digits> * 10**point. A sign, if present, is ignored — callers pass it to #render separately.
      #
      # @param string [String]
      # @return [Array(String, Integer)]
      # rubocop:disable Metrics/AbcSize
      def self.shortest_digits(string)
        mantissa, exponent = string.sub(/\A-/, "").split(/e/i)
        integer_part, fraction = mantissa.to_s.split(".")
        integer_part = integer_part.to_s
        combined = integer_part + fraction.to_s
        without_leading = combined.sub(/\A0+/, "")
        point = integer_part.length + (exponent || "0").to_i - (combined.length - without_leading.length)
        digits = strip_trailing_zeros(without_leading)
        digits.empty? ? ["0", 1] : [digits, point]
      end
      # rubocop:enable Metrics/AbcSize

      # Drop trailing '0' digits via a single reverse scan to the last significant digit. Avoids an
      # anchored `/0+\z/` (which a regex engine can match in polynomial time on adversarial all-zero
      # runs); the negated single-character class has no quantifier to backtrack on.
      #
      # @param string [String]
      # @return [String]
      def self.strip_trailing_zeros(string)
        last_significant = string.rindex(/[^0]/)
        last_significant ? string[0..last_significant].to_s : ""
      end

      # @return [String]
      def self.fixed(digits, point)
        length = digits.length
        return "0.#{"0" * -point}#{digits}" if point <= 0
        return digits + ("0" * (point - length)) if point >= length

        "#{digits[0...point]}.#{digits[point..]}"
      end

      # @return [String]
      def self.scientific(digits, exponent)
        mantissa = digits.length == 1 ? digits : "#{digits[0]}.#{digits[1..]}"
        "#{mantissa}e#{exponent.negative? ? "-" : "+"}#{format("%02d", exponent.abs)}"
      end
    end
  end
end
