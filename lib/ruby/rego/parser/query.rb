# frozen_string_literal: true

module Ruby
  module Rego
    # Parsing helpers for queries.
    class Parser
      private

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

      def parse_every
        keyword = consume(TokenType::EVERY, "Expected 'every' expression.")
        key_var, value_var = parse_every_variables
        domain = parse_every_domain
        body = parse_every_body
        AST::Every.new(key_var: key_var, value_var: value_var, domain: domain, body: body, location: keyword.location)
      end

      def parse_every_variables
        value_var = parse_variable
        return [nil, value_var] unless match?(TokenType::COMMA)

        advance
        [value_var, parse_variable]
      end

      def parse_every_domain
        consume(TokenType::IN, "Expected 'in' after every variables.")
        parse_expression
      end

      # :reek:TooManyStatements
      def parse_every_body
        consume_newlines
        consume(TokenType::LBRACE, "Expected '{' to start every body.")
        consume_newlines
        body = parse_query(TokenType::RBRACE, newline_delimiter: true)
        consume(TokenType::RBRACE, "Expected '}' after every body.")
        body
      end

      def parse_with_modifier
        keyword = consume(TokenType::WITH, "Expected 'with' modifier.")
        target = parse_expression
        consume(TokenType::AS, "Expected 'as' after with target.")
        value = parse_expression
        AST::WithModifier.new(target: target, value: value, location: keyword.location)
      end
    end
  end
end
