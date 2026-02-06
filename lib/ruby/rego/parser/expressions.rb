# frozen_string_literal: true

module Ruby
  module Rego
    # Parsing helpers for expressions.
    class Parser
      private

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

      # :reek:TooManyStatements
      def parse_call_args
        parse_parenthesized_expression_list(
          open_message: "Expected '('.",
          close_message: "Expected ')' after arguments."
        )
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
      def parse_parenthesized_expression_list(open_message:, close_message:)
        consume(TokenType::LPAREN, open_message)
        consume_newlines
        args = [] # @type var args: Array[AST::expression]
        args = parse_expression_list_until(TokenType::RPAREN) unless match?(TokenType::RPAREN)
        consume_newlines
        consume(TokenType::RPAREN, close_message)
        args
      end
    end
  end
end
