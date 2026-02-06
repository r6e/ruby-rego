# frozen_string_literal: true

module Ruby
  module Rego
    # Lexer helpers for string literals.
    class Lexer
      private

      # rubocop:disable Metrics/MethodLength
      def read_string
        start = capture_position
        advance
        buffer = +""

        until eof?
          char_position = capture_position
          char = advance
          return build_token(TokenType::STRING, buffer, start) if char == "\""

          break if char == "\n"

          buffer << (char == "\\" ? read_escape_sequence(char_position) : char)
        end

        raise_unterminated_string(start)
      end
      # rubocop:enable Metrics/MethodLength

      # rubocop:disable Metrics/MethodLength
      def read_raw_string
        start = capture_position
        advance
        buffer = +""

        until eof?
          char = advance
          return build_token(TokenType::RAW_STRING, buffer, start) if char == "`"

          if char == "\\" && current_char == "{"
            advance
            buffer << "{"
          else
            buffer << char
          end
        end

        raise_unterminated_raw_string(start)
      end
      # rubocop:enable Metrics/MethodLength

      # rubocop:disable Metrics/MethodLength, Metrics/CyclomaticComplexity
      def read_escape_sequence(backslash_position)
        char = current_char
        raise_unterminated_string(backslash_position) if char.nil? || char == "\n"

        advance

        case char
        when "\"", "\\", "/", "{"
          char
        when "b"
          "\b"
        when "f"
          "\f"
        when "n"
          "\n"
        when "r"
          "\r"
        when "t"
          "\t"
        when "u"
          read_unicode_escape
        else
          raise_error("Invalid escape sequence: \\#{char}", backslash_position, length: 2)
        end
      end
      # rubocop:enable Metrics/MethodLength, Metrics/CyclomaticComplexity

      def read_unicode_escape
        hex = +""

        4.times do
          char = current_char.to_s
          raise_error("Invalid unicode escape sequence", capture_position, length: 1) unless hex_digit?(char)

          advance
          hex << char
        end

        [hex.to_i(16)].pack("U")
      end
    end
  end
end
