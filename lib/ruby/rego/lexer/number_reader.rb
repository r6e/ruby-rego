# frozen_string_literal: true

module Ruby
  module Rego
    # Lexer helpers for numeric literals.
    class Lexer
      private

      def read_number
        start = capture_position
        buffer = read_number_prefix
        buffer << read_fractional_part
        buffer << read_exponent_part
        build_token(TokenType::NUMBER, parse_number(buffer, start), start)
      end

      def read_number_prefix
        buffer = +""
        buffer << advance
        raise_error("Invalid number literal", capture_position, length: 1) if buffer == "0" && digit?(current_char)
        buffer << read_digits
        buffer
      end

      def read_fractional_part
        return "" unless current_char == "."

        raise_error("Invalid number literal", capture_position, length: 1) unless digit?(peek(1))
        buffer = +""
        buffer << advance
        buffer << read_digits
        buffer
      end

      def read_exponent_part
        return "" unless exponent_start?

        buffer = +""
        buffer << advance
        buffer << read_exponent_sign
        raise_error("Invalid number exponent", capture_position, length: 1) unless digit?(current_char)
        buffer << read_digits
        buffer
      end

      def read_exponent_sign
        sign = current_char
        return "" unless sign && SIGN_CHARS.include?(sign)

        advance
      end

      def read_digits
        digits = +""
        digits << advance while digit?(current_char)
        digits
      end

      # A number with a fraction or exponent becomes an arbitrary-precision Number that preserves its
      # source text verbatim (OPA's json.Number model: `1.50` stays `1.50`, `1e999` stays `1e999`),
      # rather than collapsing to an IEEE-754 Float. A plain integer stays a Ruby Integer. A literal whose
      # magnitude is beyond OPA's limit is rejected at parse ("number too big"), matching OPA and bounding
      # the rational that the number would otherwise materialize (an unbounded-exponent DoS guard).
      def parse_number(buffer, start)
        fractional = buffer.include?(".") || buffer.match?(/[eE]/)
        reject_oversized_number(buffer, start, fractional)
        return Number.literal(buffer) if fractional

        Integer(buffer, 10)
      rescue ArgumentError
        raise_error("Invalid number literal", start, length: buffer.length)
      end

      # Reject a literal whose magnitude is beyond OPA's limit ("number too big"), via the single gate
      # Number.magnitude_within_limit? (O(1) digit count for an integer, BigDecimal for a fractional /
      # exponent form). Matches OPA and bounds the rational the number would otherwise materialize.
      def reject_oversized_number(buffer, start, fractional)
        return if Number.magnitude_within_limit?(buffer, fractional: fractional)

        raise_error("number too big", start, length: buffer.length)
      end
    end
  end
end
