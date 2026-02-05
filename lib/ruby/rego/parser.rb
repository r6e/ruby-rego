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
        consume(TokenType::LPAREN, "Expected '(' after rule name.")
        consume_newlines
        args = [] # @type var args: Array[AST::expression]
        args = parse_expression_list_until(TokenType::RPAREN) unless match?(TokenType::RPAREN)
        consume_newlines
        consume(TokenType::RPAREN, "Expected ')' after rule arguments.")
        args
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

      # :reek:TooManyStatements
      # :reek:DuplicateMethodCall
      # :reek:BooleanParameter
      # rubocop:disable Metrics/MethodLength
      def parse_query(*end_tokens, newline_delimiter: false)
        terminators = end_tokens.flatten
        literals = [] # @type var literals: Array[AST::query_literal]

        loop do
          consume_newlines if newline_delimiter
          break if terminators.include?(current_token.type)

          literals << parse_literal
          consume_newlines if newline_delimiter
          break if terminators.include?(current_token.type)

          break unless consume_query_separators(newline_delimiter)
        end

        literals
      end

      # rubocop:enable Metrics/MethodLength

      # rubocop:disable Metrics/MethodLength
      # :reek:TooManyStatements
      # :reek:ControlParameter
      def consume_query_separators(newline_delimiter)
        consumed = false

        loop do
          if match?(TokenType::SEMICOLON)
            advance
            consumed = true
            next
          end

          if newline_delimiter && newline_token?
            advance
            consumed = true
            next
          end

          break
        end

        consumed
      end

      # rubocop:enable Metrics/MethodLength

      def parse_literal
        return parse_some_decl if match?(TokenType::SOME)

        expression = parse_expression
        AST::QueryLiteral.new(
          expression: expression,
          with_modifiers: parse_with_modifiers,
          location: expression.location
        )
      end

      def parse_with_modifiers
        modifiers = [] # @type var modifiers: Array[AST::WithModifier]
        modifiers << parse_with_modifier while match?(TokenType::WITH)
        modifiers
      end

      def parse_some_decl
        keyword = consume(TokenType::SOME, "Expected 'some' declaration.")
        variables = parse_some_variables
        collection = parse_some_collection

        AST::SomeDecl.new(variables: variables, collection: collection, location: keyword.location)
      end

      # :reek:TooManyStatements
      def parse_some_variables
        variables = [] # @type var variables: Array[AST::Variable]
        loop do
          variables << parse_variable
          break unless match?(TokenType::COMMA)

          advance
        end
        variables
      end

      def parse_some_collection
        return nil unless match?(TokenType::IN)

        advance
        parse_expression
      end

      def parse_with_modifier
        keyword = consume(TokenType::WITH, "Expected 'with' modifier.")
        target = parse_expression
        consume(TokenType::AS, "Expected 'as' after with target.")
        value = parse_expression
        AST::WithModifier.new(target: target, value: value, location: keyword.location)
      end

      def parse_else_clause
        keyword = consume(TokenType::ELSE, "Expected 'else' clause.")
        value = nil
        value = parse_rule_value if match?(TokenType::ASSIGN, TokenType::UNIFY)
        body = parse_rule_body if match?(TokenType::IF, TokenType::LBRACE)

        { value: value, body: body, location: keyword.location }
      end

      def parse_expression(precedence = Precedence::LOWEST)
        parse_infix_expression(parse_primary, precedence)
      end

      def parse_infix_expression(left, precedence)
        return left unless infix_operator?(precedence)

        operator_token = advance
        parse_infix_expression(parse_infix(left, operator_token), precedence)
      end

      def infix_operator?(precedence)
        Helpers.precedence_of(current_token.type) > precedence
      end

      def parse_primary
        handler = PRIMARY_PARSERS[current_token.type]
        return send(handler) if handler

        parse_error("Expected expression.")
      end

      # :reek:FeatureEnvy
      def parse_infix(left, operator_token)
        operator_type = operator_token.type
        operator = BINARY_OPERATOR_MAP.fetch(operator_type) do
          parse_error("Unsupported operator: #{operator_type}.")
        end

        right = parse_expression(Helpers.precedence_of(operator_type))
        AST::BinaryOp.new(operator: operator, left: left, right: right, location: operator_token.location)
      end

      def parse_reference(base)
        reference_base, path = Helpers.normalize_reference_base(base)
        parse_reference_path(path)
        AST::Reference.new(base: reference_base, path: path, location: base.location)
      end

      # :reek:TooManyStatements
      # :reek:DuplicateMethodCall
      def parse_array
        start = consume(TokenType::LBRACKET)
        location = start.location
        consume_newlines
        return AST::ArrayLiteral.new(elements: [], location: location) if match?(TokenType::RBRACKET)

        term = parse_expression(Precedence::OR)
        return parse_array_comprehension(start, term) if pipe_token?

        elements = parse_expression_list_until_with_first(TokenType::RBRACKET, term)
        consume_newlines
        consume(TokenType::RBRACKET, "Expected ']' after array literal.")
        AST::ArrayLiteral.new(elements: elements, location: location)
      end

      def parse_object(start_token, first_key, first_value)
        pairs = build_object_pairs(first_key, first_value)
        consume_newlines
        consume(TokenType::RBRACE, "Expected '}' after object literal.")
        AST::ObjectLiteral.new(pairs: pairs, location: start_token.location)
      end

      def build_object_pairs(first_key, first_value)
        pairs = [] # @type var pairs: Array[[AST::expression, AST::expression]]
        pairs << [first_key, first_value]
        append_object_pairs(pairs)
        pairs
      end

      def parse_set(start_token, first_element = nil)
        return empty_set_literal(start_token) if empty_set?(first_element)

        elements = parse_expression_list_until_with_first(TokenType::RBRACE, first_element)
        consume_newlines
        consume(TokenType::RBRACE, "Expected '}' after set literal.")
        AST::SetLiteral.new(elements: elements, location: start_token.location)
      end

      # :reek:TooManyStatements
      def parse_call_args
        consume(TokenType::LPAREN, "Expected '('.")
        consume_newlines
        args = [] # @type var args: Array[AST::expression]
        args = parse_expression_list_until(TokenType::RPAREN) unless match?(TokenType::RPAREN)
        consume_newlines
        consume(TokenType::RPAREN, "Expected ')' after arguments.")
        args
      end

      def parse_string_literal
        token = current_token
        parse_error("Expected string literal.") unless [TokenType::STRING, TokenType::RAW_STRING].include?(token.type)
        advance
        value = token.value.to_s
        AST::StringLiteral.new(value: value, location: token.location)
      end

      # :reek:FeatureEnvy
      def parse_number_literal
        token = consume(TokenType::NUMBER, "Expected number literal.")
        value = token.value
        if value.is_a?(String)
          value = if value.match?(/[eE.]/)
                    Float(value)
                  else
                    Integer(value, 10)
                  end
        end
        AST::NumberLiteral.new(value: value, location: token.location)
      end

      def parse_boolean_literal
        token_type = current_token.type
        location = current_token.location
        advance
        AST::BooleanLiteral.new(value: token_type == TokenType::TRUE, location: location)
      end

      def parse_null_literal
        token = advance
        AST::NullLiteral.new(location: token.location)
      end

      def parse_unary_expression
        token = advance
        operator = UNARY_OPERATOR_MAP.fetch(token.type)
        operand = parse_expression(Precedence::UNARY)
        AST::UnaryOp.new(operator: operator, operand: operand, location: token.location)
      end

      def parse_parenthesized_expression
        advance
        expression = parse_parenthesized_body
        consume(TokenType::RPAREN, "Expected ')' after expression.")
        expression
      end

      def parse_parenthesized_body
        consume_newlines
        expression = parse_expression
        consume_newlines
        expression
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

      # :reek:TooManyStatements
      def parse_braced_literal
        start = consume(TokenType::LBRACE)
        consume_newlines
        return parse_set(start) if rbrace_token?

        first = parse_expression(Precedence::OR)
        return parse_set_comprehension(start, first) if pipe_token?
        return parse_object_literal_or_comprehension(start, first) if match?(TokenType::COLON)

        parse_set(start, first)
      end

      def parse_object_literal_or_comprehension(start, key)
        advance
        consume_newlines
        value = parse_expression(Precedence::OR)
        return parse_object_comprehension(start, key, value) if pipe_token?

        parse_object(start, key, value)
      end

      def parse_identifier_expression
        base = parse_variable
        base = parse_reference(base) if match?(TokenType::DOT, TokenType::LBRACKET)
        return base unless match?(TokenType::LPAREN)

        AST::Call.new(name: base, args: parse_call_args, location: base.location)
      end

      def parse_variable
        token = current_token
        name = Helpers.variable_name_for(token)
        advance
        AST::Variable.new(name: name, location: token.location)
      end

      def parse_expression_list_until(end_token)
        elements = [] # @type var elements: Array[AST::expression]
        consume_newlines
        elements << parse_expression
        append_expression_list(elements, end_token)
        elements
      end

      def parse_expression_list_until_with_first(end_token, first_element)
        elements = [] # @type var elements: Array[AST::expression]
        elements << first_element
        consume_newlines
        append_expression_list(elements, end_token)
        elements
      end

      def parse_object_pair(key)
        consume(TokenType::COLON, "Expected ':' after object key.")
        consume_newlines
        value = parse_expression
        [key, value]
      end

      def append_expression_list(elements, end_token)
        while match?(TokenType::COMMA)
          advance
          consume_newlines
          break if match?(end_token)

          elements << parse_expression
        end
      end

      def append_object_pairs(pairs)
        while match?(TokenType::COMMA)
          advance
          consume_newlines
          break if rbrace_token?

          pairs << parse_object_pair(parse_expression)
        end
      end

      def parse_array_comprehension(start_token, term)
        consume(TokenType::PIPE, "Expected '|' after array term.")
        body = parse_query(TokenType::RBRACKET, newline_delimiter: true)
        consume(TokenType::RBRACKET, "Expected ']' after array comprehension.")
        AST::ArrayComprehension.new(term: term, body: body, location: start_token.location)
      end

      def parse_object_comprehension(start_token, key, value)
        consume(TokenType::PIPE, "Expected '|' after object term.")
        body = parse_query(TokenType::RBRACE, newline_delimiter: true)
        consume(TokenType::RBRACE, "Expected '}' after object comprehension.")
        AST::ObjectComprehension.new(term: [key, value], body: body, location: start_token.location)
      end

      def parse_set_comprehension(start_token, term)
        consume(TokenType::PIPE, "Expected '|' after set term.")
        body = parse_query(TokenType::RBRACE, newline_delimiter: true)
        consume(TokenType::RBRACE, "Expected '}' after set comprehension.")
        AST::SetComprehension.new(term: term, body: body, location: start_token.location)
      end

      def parse_reference_path(path)
        while match?(TokenType::DOT, TokenType::LBRACKET)
          match?(TokenType::DOT) ? parse_dot_reference(path) : parse_bracket_reference(path)
        end
      end

      def parse_dot_reference(path)
        advance
        segment_token = current_token
        segment = parse_identifier(IdentifierContext.new(name: "reference", allowed_types: IDENTIFIER_TOKEN_TYPES))
        path << AST::DotRefArg.new(value: segment, location: segment_token.location)
      end

      def parse_bracket_reference(path)
        bracket_token = consume(TokenType::LBRACKET)
        value = parse_expression
        consume(TokenType::RBRACKET, "Expected ']' after reference path.")
        path << AST::BracketRefArg.new(value: value, location: bracket_token.location)
      end

      def empty_set?(first_element)
        rbrace_token? && !first_element
      end

      def empty_set_literal(start_token)
        advance
        AST::SetLiteral.new(elements: [], location: start_token.location)
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
