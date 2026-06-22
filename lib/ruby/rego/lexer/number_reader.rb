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
      # rather than collapsing to an IEEE-754 Float. A plain integer stays a Ruby Integer.
      def parse_number(buffer, start)
        return Number.literal(buffer) if buffer.include?(".") || buffer.match?(/[eE]/)

        Integer(buffer, 10)
      rescue ArgumentError
        raise_error("Invalid number literal", start, length: buffer.length)
      end
    end
  end
end
