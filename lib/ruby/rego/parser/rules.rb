# frozen_string_literal: true

module Ruby
  module Rego
    # Parsing helpers for rules and module declarations.
    # :reek:TooManyMethods
    # :reek:DataClump
    # :reek:RepeatedConditional
    # rubocop:disable Metrics/ClassLength
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
        path = parse_path(IdentifierContext.new(name: "import", allowed_types: IMPORT_PATH_TOKEN_TYPES)).join(".")
        alias_name = parse_import_alias

        AST::Import.new(path: path, alias_name: alias_name, location: keyword.location)
      end

      def parse_import_alias
        return nil unless match?(TokenType::AS)

        advance
        parse_identifier(IdentifierContext.new(name: "import alias", allowed_types: PACKAGE_PATH_TOKEN_TYPES))
      end

      # :reek:TooManyStatements
      def parse_rule
        default_token = consume_default_keyword
        name_token = current_token
        name = parse_rule_name
        head = parse_rule_head(name, name_token)
        head = mark_default_head(head) if default_token
        definition = parse_rule_definition(default_token, head)
        validate_rule_definition(default_token, head, definition)

        build_rule_node(name: name, head: head, name_token: name_token, definition: definition)
      end

      def consume_default_keyword
        match?(TokenType::DEFAULT) ? advance : nil
      end

      def parse_rule_name
        parse_identifier(IdentifierContext.new(name: "rule", allowed_types: PACKAGE_PATH_TOKEN_TYPES))
      end

      # :reek:UtilityFunction
      def mark_default_head(head)
        head.merge(default: true)
      end

      # :reek:NilCheck
      # :reek:ControlParameter
      def parse_default_value(default_token, head)
        return nil unless default_token

        default_value = head[:value]
        parse_error("Expected default rule value.") if default_value.nil?
        default_value
      end

      # :reek:ControlParameter
      def parse_non_default_body(default_token)
        return nil if default_token
        return nil unless match?(TokenType::IF, TokenType::LBRACE)

        parse_rule_body
      end

      def parse_rule_definition(default_token, head)
        default_value = parse_default_value(default_token, head)
        body = parse_non_default_body(default_token)
        else_clause = parse_else_clause_for_definition(default_token)

        {
          default_value: default_value,
          body: body,
          else_clause: else_clause
        }
      end

      # :reek:ControlParameter
      def parse_else_clause_for_definition(default_token)
        consume_newlines
        parse_error("Default rules cannot have else clauses.") if default_token && match?(TokenType::ELSE)
        parse_else_clause_if_present
      end

      # :reek:FeatureEnvy
      # :reek:ControlParameter
      def validate_rule_definition(default_token, head, definition)
        return if default_token
        return unless head[:type] == :complete
        return if head[:value] || definition[:body]

        parse_error("Expected rule body or value.")
      end

      def parse_else_clause_if_present
        return nil unless match?(TokenType::ELSE)

        parse_else_clause
      end

      # :reek:UtilityFunction
      # :reek:LongParameterList
      def build_rule_node(name:, head:, name_token:, definition:)
        AST::Rule.new(
          name: name,
          head: head,
          body: definition[:body],
          default_value: definition[:default_value],
          else_clause: definition[:else_clause],
          location: name_token.location
        )
      end

      def parse_rule_head(name, name_token)
        return parse_contains_rule_head(name, name_token) if match?(TokenType::CONTAINS)
        return parse_function_rule_head(name, name_token) if match?(TokenType::LPAREN)
        return parse_bracket_rule_head(name, name_token) if match?(TokenType::LBRACKET)

        build_rule_head(:complete, name, name_token, value: parse_rule_value)
      end

      def parse_contains_rule_head(name, name_token)
        advance
        term = parse_expression
        build_rule_head(:partial_set, name, name_token, term: term)
      end

      def parse_function_rule_head(name, name_token)
        args = parse_rule_head_args
        value = parse_rule_value
        build_rule_head(:function, name, name_token, args: args, value: value)
      end

      def parse_bracket_rule_head(name, name_token)
        key = parse_rule_head_key
        return parse_partial_object_rule_head(name, name_token, key) if match?(TokenType::ASSIGN, TokenType::UNIFY)

        build_rule_head(:partial_set, name, name_token, term: key)
      end

      def parse_partial_object_rule_head(name, name_token, key)
        advance
        value = parse_expression
        build_rule_head(:partial_object, name, name_token, key: key, value: value)
      end

      # :reek:UtilityFunction
      # :reek:LongParameterList
      def build_rule_head(type, name, name_token, **attrs)
        { type: type, name: name, location: name_token.location }.merge(attrs)
      end

      # :reek:TooManyStatements
      def parse_rule_head_args
        parse_parenthesized_expression_list(
          open_message: "Expected '(' after rule name.",
          close_message: "Expected ')' after rule arguments."
        )
      end

      # :reek:TooManyStatements
      def parse_rule_head_key
        consume(TokenType::LBRACKET, "Expected '[' after rule name.")
        consume_newlines
        key = parse_expression
        consume_newlines
        consume(TokenType::RBRACKET, "Expected ']' after rule key.")
        key
      end

      def parse_rule_value
        return nil unless match?(TokenType::ASSIGN, TokenType::UNIFY)

        advance
        parse_expression
      end

      def parse_rule_body
        advance if match?(TokenType::IF)
        return parse_braced_rule_body if match?(TokenType::LBRACE)

        parse_query(TokenType::ELSE, TokenType::EOF, TokenType::NEWLINE, newline_delimiter: false)
      end

      # :reek:TooManyStatements
      def parse_braced_rule_body
        advance
        consume_newlines
        return parse_empty_rule_body if rbrace_token?

        body = parse_query(TokenType::RBRACE, newline_delimiter: true)
        consume(TokenType::RBRACE, "Expected '}' after rule body.")
        body
      end

      def parse_empty_rule_body
        advance
        []
      end

      def parse_else_clause
        keyword = consume(TokenType::ELSE, "Expected 'else' clause.")
        value = nil
        value = parse_rule_value if match?(TokenType::ASSIGN, TokenType::UNIFY)
        body = parse_rule_body if match?(TokenType::IF, TokenType::LBRACE)

        { value: value, body: body, location: keyword.location }
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
end
