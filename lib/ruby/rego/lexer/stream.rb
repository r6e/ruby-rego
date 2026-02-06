# frozen_string_literal: true

module Ruby
  module Rego
    # Stream helpers for lexer traversal and errors.
    # :reek:InstanceVariableAssumption
    class Lexer
      private

      def advance
        char = current_char
        raise_unexpected_eof if char.nil?

        return advance_line_break if char == "\r"
        return advance_newline if char == "\n"

        increment_position(1)
        char
      end

      def advance_line_break
        increment_line(peek == "\n" ? 2 : 1)
        "\n"
      end

      def advance_newline
        increment_line(1)
        "\n"
      end

      def increment_line(count)
        @position += count
        @offset += count
        @line += 1
        @column = 1
      end

      def increment_position(count)
        @position += count
        @offset += count
        @column += count
      end

      def peek(distance = 1)
        source[@position + distance]
      end

      def match?(expected)
        return false unless current_char == expected

        advance
        true
      end

      def current_char
        source[@position]
      end

      def eof?
        @position >= source.length
      end

      def capture_position
        { line: line, column: column, offset: offset }
      end

      def build_token(type, value, start)
        start_offset = start.fetch(:offset) || 0
        length = offset - start_offset
        location = Location.new(
          line: start.fetch(:line),
          column: start.fetch(:column),
          offset: start_offset,
          length: length
        )
        Token.new(type: type, value: value, location: location)
      end

      def identifier_start?(char)
        !!(char && char.match?(IDENTIFIER_START))
      end

      def identifier_part?(char)
        !!(char && char.match?(IDENTIFIER_PART))
      end

      def digit?(char)
        !!(char && char.match?(DIGIT))
      end

      def hex_digit?(char)
        !!(char && char.match?(HEX_DIGIT))
      end

      def whitespace?(char)
        return false if char.nil?

        WHITESPACE_CHARS.include?(char)
      end

      def newline?(char)
        return false if char.nil?

        NEWLINE_CHARS.include?(char)
      end

      def exponent_start?
        char = current_char
        !!(char && EXPONENT_CHARS.include?(char))
      end

      def span_length_from(start)
        start_offset = start.fetch(:offset) || 0
        offset - start_offset
      end

      def raise_unterminated_string(start)
        raise_error("Unterminated string literal", start, length: span_length_from(start))
      end

      def raise_unterminated_raw_string(start)
        raise_error("Unterminated raw string literal", start, length: span_length_from(start))
      end

      def raise_unexpected_eof
        raise_error("Unexpected end of input", capture_position, length: 0)
      end

      def raise_error(message, position, length: nil)
        line_value = position.fetch(:line)
        column_value = position.fetch(:column)
        offset_value = position.fetch(:offset) || 0
        raise LexerError.new(message, line: line_value, column: column_value, offset: offset_value, length: length)
      end
    end
  end
end
