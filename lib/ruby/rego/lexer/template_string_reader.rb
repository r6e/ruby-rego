# frozen_string_literal: true

module Ruby
  module Rego
    # Template string lexer helpers.
    class Lexer
      private

      # rubocop:disable Metrics/MethodLength
      def read_template_string
        start = capture_position
        advance
        return read_raw_template_string(start) if current_char == "`"

        read_standard_template_string(start)
      end

      def read_standard_template_string(start)
        advance
        buffer = +""

        until eof?
          char_position = capture_position
          char = advance
          return build_token(TokenType::TEMPLATE_STRING, buffer, start) if char == "\""

          break if char == "\n"

          if char == "\\" && current_char == "{"
            advance
            buffer << TEMPLATE_ESCAPE
            next
          end

          buffer << (char == "\\" ? read_escape_sequence(char_position) : char)
        end

        raise_unterminated_string(start)
      end

      def read_raw_template_string(start)
        advance
        buffer = +""

        until eof?
          char = advance
          return build_token(TokenType::RAW_TEMPLATE_STRING, buffer, start) if char == "`"

          if char == "\\" && current_char == "{"
            advance
            buffer << TEMPLATE_ESCAPE
          else
            buffer << char
          end
        end

        raise_unterminated_raw_string(start)
      end
      # rubocop:enable Metrics/MethodLength
    end
  end
end
