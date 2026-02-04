# frozen_string_literal: true

require_relative "errors"
require_relative "location"
require_relative "token"

module Ruby
  module Rego
    # Converts Rego source code into a stream of tokens.
    # rubocop:disable Metrics/ClassLength
    class Lexer
      KEYWORDS = {
        "package" => TokenType::PACKAGE,
        "import" => TokenType::IMPORT,
        "as" => TokenType::AS,
        "default" => TokenType::DEFAULT,
        "if" => TokenType::IF,
        "contains" => TokenType::CONTAINS,
        "some" => TokenType::SOME,
        "in" => TokenType::IN,
        "every" => TokenType::EVERY,
        "not" => TokenType::NOT,
        "with" => TokenType::WITH,
        "else" => TokenType::ELSE,
        "true" => TokenType::TRUE,
        "false" => TokenType::FALSE,
        "null" => TokenType::NULL,
        "data" => TokenType::DATA,
        "input" => TokenType::INPUT
      }.freeze

      SINGLE_CHAR_TOKENS = {
        "(" => TokenType::LPAREN,
        ")" => TokenType::RPAREN,
        "[" => TokenType::LBRACKET,
        "]" => TokenType::RBRACKET,
        "{" => TokenType::LBRACE,
        "}" => TokenType::RBRACE,
        "." => TokenType::DOT,
        "," => TokenType::COMMA,
        ";" => TokenType::SEMICOLON,
        "+" => TokenType::PLUS,
        "-" => TokenType::MINUS,
        "*" => TokenType::STAR,
        "/" => TokenType::SLASH,
        "%" => TokenType::PERCENT,
        "|" => TokenType::PIPE,
        "&" => TokenType::AMPERSAND
      }.freeze

      NEWLINE_CHARS = ["\n", "\r"].freeze
      WHITESPACE_CHARS = [" ", "\t"].freeze
      EXPONENT_CHARS = %w[e E].freeze
      SIGN_CHARS = %w[+ -].freeze

      IDENTIFIER_START = /[A-Za-z_]/
      IDENTIFIER_PART = /[A-Za-z0-9_]/
      DIGIT = /\d/
      HEX_DIGIT = /[0-9A-Fa-f]/

      # @param source [String]
      def initialize(source)
        @source = source.to_s
        @position = 0
        @line = 1
        @column = 1
        @offset = 0
      end

      # @return [Array<Token>]
      def tokenize
        # @type var tokens: Array[Token]
        tokens = []

        loop do
          skip_whitespace
          break if eof?

          tokens << next_token
        end

        tokens << eof_token
        tokens
      end

      private

      attr_reader :source, :position, :line, :column, :offset

      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
      def next_token
        char = current_char
        return eof_token if char.nil?

        return read_number if digit?(char)
        return read_identifier if identifier_start?(char)
        return read_string if char == "\""
        return read_raw_string if char == "`"

        raise_error("Invalid number literal", capture_position, length: 1) if char == "." && digit?(peek(1))

        token = simple_token_for(char)
        return token if token

        case char
        when ":"
          read_colon_or_assign
        when "="
          read_equal_or_unify
        when "!"
          read_not_equal
        when "<"
          read_lt_or_lte
        when ">"
          read_gt_or_gte
        else
          raise_error("Unexpected character: #{char.inspect}", capture_position, length: 1)
        end
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity

      def eof_token
        start = capture_position
        build_token(TokenType::EOF, nil, start)
      end

      def simple_token_for(char)
        type = SINGLE_CHAR_TOKENS[char]
        return nil unless type

        start = capture_position
        advance
        build_token(type, nil, start)
      end

      def read_colon_or_assign
        start = capture_position
        advance
        return build_token(TokenType::ASSIGN, nil, start) if match?("=")

        build_token(TokenType::COLON, nil, start)
      end

      def read_equal_or_unify
        start = capture_position
        advance
        return build_token(TokenType::EQ, nil, start) if match?("=")

        build_token(TokenType::UNIFY, nil, start)
      end

      def read_not_equal
        start = capture_position
        advance
        return build_token(TokenType::NEQ, nil, start) if match?("=")

        raise_error("Unexpected character: #{"!".inspect}", start, length: 1)
      end

      def read_lt_or_lte
        start = capture_position
        advance
        return build_token(TokenType::LTE, nil, start) if match?("=")

        build_token(TokenType::LT, nil, start)
      end

      def read_gt_or_gte
        start = capture_position
        advance
        return build_token(TokenType::GTE, nil, start) if match?("=")

        build_token(TokenType::GT, nil, start)
      end

      def skip_whitespace
        loop do
          char = current_char
          break if char.nil?

          if char == "#"
            skip_comment
            next
          end

          break unless whitespace?(char)

          advance
        end
      end

      def skip_comment
        advance
        advance until eof? || newline?(current_char)
      end

      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
      def read_number
        start = capture_position
        buffer = +""

        buffer << advance

        raise_error("Invalid number literal", capture_position, length: 1) if buffer == "0" && digit?(current_char)

        buffer << read_digits

        if current_char == "."
          if digit?(peek(1))
            buffer << advance
            buffer << read_digits
          else
            raise_error("Invalid number literal", capture_position, length: 1)
          end
        end

        if exponent_start?
          buffer << advance
          sign = current_char
          buffer << advance if sign && SIGN_CHARS.include?(sign)
          raise_error("Invalid number exponent", capture_position, length: 1) unless digit?(current_char)
          buffer << read_digits
        end

        build_token(TokenType::NUMBER, parse_number(buffer, start), start)
      end
      # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

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

      def read_identifier
        start = capture_position
        buffer = +""

        buffer << advance while identifier_part?(current_char)

        return build_token(TokenType::UNDERSCORE, nil, start) if buffer == "_"

        keyword = KEYWORDS[buffer]
        return build_token(keyword, nil, start) if keyword

        build_token(TokenType::IDENT, buffer, start)
      end

      def read_digits
        digits = +""
        digits << advance while digit?(current_char)
        digits
      end

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

      def parse_number(buffer, start)
        return Float(buffer) if buffer.include?(".") || buffer.match?(/[eE]/)

        Integer(buffer, 10)
      rescue ArgumentError
        raise_error("Invalid number literal", start, length: buffer.length)
      end

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

        WHITESPACE_CHARS.include?(char) || newline?(char)
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
    # rubocop:enable Metrics/ClassLength
  end
end
