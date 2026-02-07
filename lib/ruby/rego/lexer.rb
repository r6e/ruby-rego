# frozen_string_literal: true

require_relative "errors"
require_relative "location"
require_relative "token"
require_relative "lexer/number_reader"
require_relative "lexer/stream"
require_relative "lexer/string_reader"

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

      COMPOUND_TOKENS = {
        ":" => [TokenType::COLON, TokenType::ASSIGN],
        "=" => [TokenType::UNIFY, TokenType::EQ],
        "!" => [nil, TokenType::NEQ],
        "<" => [TokenType::LT, TokenType::LTE],
        ">" => [TokenType::GT, TokenType::GTE]
      }.freeze

      NEWLINE_CHARS = ["\n", "\r"].freeze
      WHITESPACE_CHARS = [" ", "\t"].freeze
      EXPONENT_CHARS = %w[e E].freeze
      SIGN_CHARS = %w[+ -].freeze

      IDENTIFIER_START = /[A-Za-z_]/
      IDENTIFIER_PART = /[A-Za-z0-9_]/
      DIGIT = /\d/
      HEX_DIGIT = /[0-9A-Fa-f]/

      # Create a lexer for the provided source.
      #
      # @param source [String] Rego source code
      def initialize(source)
        @source = source.to_s
        @position = 0
        @line = 1
        @column = 1
        @offset = 0
      end

      # Tokenize the source into a list of tokens, including EOF.
      #
      # @return [Array<Token>] token stream
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

        return read_newline if newline?(char)
        return read_number if digit?(char)
        return read_identifier if identifier_start?(char)
        return read_string if char == "\""
        return read_raw_string if char == "`"

        raise_error("Invalid number literal", capture_position, length: 1) if char == "." && digit?(peek(1))

        token = simple_token_for(char)
        return token if token

        token = read_compound_token(char)
        return token if token

        raise_error("Unexpected character: #{char.inspect}", capture_position, length: 1)
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

      def read_compound_token(char)
        config = COMPOUND_TOKENS[char]
        return nil unless config

        single_type, double_type = config
        start = capture_position
        advance
        return build_token(double_type, nil, start) if match?("=")
        return build_token(single_type, nil, start) if single_type

        raise_error("Unexpected character: #{char.inspect}", start, length: 1)
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

      def read_newline
        start = capture_position
        advance
        build_token(TokenType::NEWLINE, "\n", start)
      end

      def read_identifier
        start = capture_position
        buffer = +""

        buffer << advance while identifier_part?(current_char)

        return build_token(TokenType::UNDERSCORE, nil, start) if buffer == "_"

        keyword = KEYWORDS[buffer]
        return build_token(keyword, nil, start) if keyword

        build_token(TokenType::IDENT, buffer, start)
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
end
