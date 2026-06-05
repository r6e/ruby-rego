# frozen_string_literal: true

module Ruby
  module Rego
    # Parsing helpers for rules and module declarations.
    # :reek:TooManyMethods
    # :reek:DataClump
    # :reek:RepeatedConditional
    class Parser
      private

      # :reek:TooManyStatements
      def parse_module
        consume_newlines
        package = parse_package
        imports = [] # @type var imports: Array[AST::Import]
        rules = [] # @type var rules: Array[AST::Rule]

        consume_newlines
        until at_end?
          parse_statement(imports, rules)
          consume_newlines
        end

        AST::Module.new(package: package, imports: imports, rules: rules, location: package.location)
      end

      # :reek:UncommunicativeVariableName
      # :reek:TooManyStatements
      def parse_statement(imports, rules)
        consume_newlines
        return if at_end?

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
        path = parse_path(IdentifierContext.new(name: "import", allowed_types: IMPORT_PATH_TOKEN_TYPES))
        alias_name = parse_import_alias

        AST::Import.new(path: path, alias_name: alias_name, location: keyword.location)
      end

      def parse_import_alias
        return nil unless match?(TokenType::AS)

        advance
        parse_identifier(IdentifierContext.new(name: "import alias", allowed_types: PACKAGE_PATH_TOKEN_TYPES))
      end
    end
  end
end

require_relative "rule_definitions"
require_relative "rule_heads"
require_relative "rule_head_builders"
require_relative "rule_bodies"
