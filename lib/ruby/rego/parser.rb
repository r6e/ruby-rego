# frozen_string_literal: true

require_relative "errors"
require_relative "token"
require_relative "ast"
require_relative "parser/precedence"

module Ruby
  module Rego
    # Parses a token stream into an AST module.
    # rubocop:disable Metrics/ClassLength
    # :reek:TooManyMethods
    class Parser
      IDENTIFIER_TOKEN_TYPES = [TokenType::IDENT, TokenType::DATA, TokenType::INPUT].freeze
      IDENTIFIER_TOKEN_NAMES = {
        TokenType::DATA => "data",
        TokenType::INPUT => "input"
      }.freeze
      PACKAGE_PATH_TOKEN_TYPES = [TokenType::IDENT].freeze
      IMPORT_PATH_TOKEN_TYPES = IDENTIFIER_TOKEN_TYPES
      # Bundles identifier parsing configuration for error messages and validation.
      IdentifierContext = Struct.new(:name, :allowed_types, keyword_init: true)

      # @param tokens [Array<Token>]
      def initialize(tokens)
        @tokens = tokens.dup
        @current = 0
        @errors = [] # @type var errors: Array[ParserError]
      end

      # @return [AST::Module]
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
          return if match?(TokenType::SEMICOLON)
          return if match?(TokenType::PACKAGE, TokenType::IMPORT, TokenType::DEFAULT, TokenType::IDENT)

          advance
        end
      end

      def parse_module
        package = parse_package
        imports = [] # @type var imports: Array[AST::Import]
        rules = [] # @type var rules: Array[AST::Rule]

        parse_statement(imports, rules) until at_end?

        AST::Module.new(package: package, imports: imports, rules: rules, location: package.location)
      end

      # :reek:UncommunicativeVariableName
      def parse_statement(imports, rules)
        if match?(TokenType::IMPORT)
          imports << parse_import
        else
          rules << parse_rule
        end
      rescue ParserError => e
        record_error(e)
        synchronize
      end

      def parse_package
        keyword = consume(TokenType::PACKAGE, "Expected package declaration.")
        path = parse_path(IdentifierContext.new(name: "package", allowed_types: PACKAGE_PATH_TOKEN_TYPES))
        AST::Package.new(path: path, location: keyword.location)
      end

      def parse_import
        keyword = consume(TokenType::IMPORT, "Expected import declaration.")
        path = parse_path(IdentifierContext.new(name: "import", allowed_types: IMPORT_PATH_TOKEN_TYPES)).join(".")
        alias_name = parse_import_alias

        AST::Import.new(path: path, alias_name: alias_name, location: keyword.location)
      end

      def parse_import_alias
        return nil unless match?(TokenType::AS)

        advance
        parse_identifier(IdentifierContext.new(name: "import alias", allowed_types: PACKAGE_PATH_TOKEN_TYPES))
      end

      def parse_rule
        parse_error("Rule parsing not implemented yet.")
      end

      def parse_expression
        parse_error("Expression parsing not implemented yet.")
      end

      # :reek:TooManyStatements
      def parse_path(identifier_context)
        segments = [] # @type var segments: Array[String]

        loop do
          segments << parse_path_segment(identifier_context)
          break unless match?(TokenType::DOT)

          advance
        end

        segments
      end

      def parse_path_segment(identifier_context)
        token_type = current_token.type
        return parse_identifier(identifier_context) if identifier_context.allowed_types.include?(token_type)

        parse_error("Expected #{identifier_context.name} identifier.")
      end

      # :reek:TooManyStatements
      def parse_identifier(identifier_context)
        context_name = identifier_context.name
        allowed_types = identifier_context.allowed_types
        token = current_token
        token_type = token.type

        parse_error("Expected #{context_name} identifier.") unless allowed_types.include?(token_type)

        advance
        return token.value.to_s if token_type == TokenType::IDENT

        IDENTIFIER_TOKEN_NAMES.fetch(token_type) { token_type.to_s.downcase }
      end

      def record_error(error)
        errors << error
      end

      def safe_token_at(index)
        tokens[index] || tokens[-1]
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
end
