# frozen_string_literal: true

require_relative "errors"
require_relative "token"
require_relative "ast"
require_relative "parser/precedence"
require_relative "parser/collections"
require_relative "parser/expressions"
require_relative "parser/query"
require_relative "parser/references"
require_relative "parser/rules"

module Ruby
  module Rego
    # Parses a token stream into an AST module.
    # rubocop:disable Metrics/ClassLength
    # :reek:TooManyMethods
    # :reek:TooManyConstants
    # :reek:RepeatedConditional
    # :reek:DataClump
    class Parser
      IDENTIFIER_TOKEN_TYPES = [TokenType::IDENT, TokenType::DATA, TokenType::INPUT].freeze
      IDENTIFIER_TOKEN_NAMES = {
        TokenType::DATA => "data",
        TokenType::INPUT => "input"
      }.freeze
      BINARY_OPERATOR_MAP = {
        TokenType::ASSIGN => :assign,
        TokenType::UNIFY => :unify,
        TokenType::PIPE => :or,
        TokenType::AMPERSAND => :and,
        TokenType::EQ => :eq,
        TokenType::NEQ => :neq,
        TokenType::LT => :lt,
        TokenType::LTE => :lte,
        TokenType::GT => :gt,
        TokenType::GTE => :gte,
        TokenType::PLUS => :plus,
        TokenType::MINUS => :minus,
        TokenType::STAR => :mult,
        TokenType::SLASH => :div,
        TokenType::PERCENT => :mod
      }.freeze
      UNARY_OPERATOR_MAP = {
        TokenType::NOT => :not,
        TokenType::MINUS => :minus
      }.freeze
      PRIMARY_PARSERS = {
        TokenType::STRING => :parse_string_literal,
        TokenType::RAW_STRING => :parse_string_literal,
        TokenType::NUMBER => :parse_number_literal,
        TokenType::TRUE => :parse_boolean_literal,
        TokenType::FALSE => :parse_boolean_literal,
        TokenType::NULL => :parse_null_literal,
        TokenType::NOT => :parse_unary_expression,
        TokenType::MINUS => :parse_unary_expression,
        TokenType::EVERY => :parse_every,
        TokenType::LPAREN => :parse_parenthesized_expression,
        TokenType::LBRACKET => :parse_array,
        TokenType::LBRACE => :parse_braced_literal,
        TokenType::IDENT => :parse_identifier_expression,
        TokenType::DATA => :parse_identifier_expression,
        TokenType::INPUT => :parse_identifier_expression,
        TokenType::UNDERSCORE => :parse_identifier_expression
      }.freeze
      PACKAGE_PATH_TOKEN_TYPES = [TokenType::IDENT].freeze
      IMPORT_PATH_TOKEN_TYPES = IDENTIFIER_TOKEN_TYPES
      # Bundles identifier parsing configuration for error messages and validation.
      IdentifierContext = Struct.new(:name, :allowed_types, keyword_init: true)

      # Create a parser from a token list.
      #
      # @param tokens [Array<Token>] token stream
      def initialize(tokens)
        @tokens = tokens.dup
        @current = 0
        @errors = [] # @type var errors: Array[ParserError]
      end

      # Parse the token stream into an AST module.
      #
      # @return [AST::Module] parsed module
      def parse
        module_node = parse_module
        raise errors.first if errors.any?

        module_node
      end

      private

      attr_reader :errors, :tokens

      def current_token
        safe_token_at(@current)
      end

      def peek(distance = 1)
        safe_token_at(@current + distance)
      end

      def advance
        previous = current_token
        @current += 1 unless at_end?
        previous
      end

      # :reek:ControlParameter
      def consume(type, message = nil)
        return advance if match?(type)

        parse_error(message || "Expected #{type} but found #{current_token.type}.")
      end

      def match?(*types)
        types.include?(current_token.type)
      end

      def pipe_token?
        match?(TokenType::PIPE)
      end

      def rbrace_token?
        match?(TokenType::RBRACE)
      end

      def newline_token?
        match?(TokenType::NEWLINE)
      end

      def consume_newlines
        advance while newline_token?
      end

      def at_end?
        current_token.type == TokenType::EOF
      end

      def parse_error(message)
        token = current_token
        position = token&.location || { line: 1, column: 1 }
        raise ParserError.from_position(message, position: position, context: token&.to_s)
      end

      def synchronize
        advance

        until at_end?
          return if match?(TokenType::SEMICOLON, TokenType::NEWLINE)
          return if match?(TokenType::PACKAGE, TokenType::IMPORT, TokenType::DEFAULT, TokenType::IDENT)

          advance
        end
      end

      def record_error(error)
        errors << error
      end

      # Shared parsing helpers that do not depend on parser state.
      module Helpers
        def self.precedence_of(operator)
          Precedence::BINARY.fetch(operator, Precedence::LOWEST)
        end

        def self.normalize_reference_base(base)
          path = [] # @type var path: Array[AST::RefArg]
          return [base, path] unless base.is_a?(AST::Reference)

          reference = base # @type var reference: AST::Reference
          [reference.base, reference.path.dup]
        end

        def self.variable_name_for(token)
          token_type = token.type
          case token_type
          when TokenType::IDENT
            token.value.to_s
          when TokenType::UNDERSCORE
            "_"
          else
            IDENTIFIER_TOKEN_NAMES.fetch(token_type) { token_type.to_s.downcase }
          end
        end
      end

      def safe_token_at(index)
        tokens[index] || tokens[-1]
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
end
