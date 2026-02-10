# frozen_string_literal: true

module Ruby
  module Rego
    # Parsing helpers for expressions.
    # rubocop:disable Metrics/ClassLength
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

      def parse_template_string
        token = current_token
        unless [TokenType::TEMPLATE_STRING, TokenType::RAW_TEMPLATE_STRING].include?(token.type)
          parse_error("Expected template string literal.")
        end
        advance
        AST::TemplateString.new(parts: parse_template_parts(token), location: token.location)
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

      # :reek:NilCheck
      # :reek:DuplicateMethodCall
      # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
      def parse_template_parts(token)
        text = token.value.to_s
        location = token.location
        parts = [] # @type var parts: Array[Object]
        index = 0

        while index < text.length
          start = text.index("{", index)
          if start.nil?
            literal = text[index..]
            append_template_literal(parts, literal, location)
            break
          end

          if start > index
            literal = text[index...start]
            append_template_literal(parts, literal, location)
          end

          expr_start = start + 1
          expr_end = find_template_expression_end(text, expr_start)
          expr_source = text[expr_start...expr_end]
          parts << self.class.parse_expression_from_string(expr_source)
          index = expr_end + 1
        end

        parts = [AST::StringLiteral.new(value: "", location: location)] if parts.empty?
        parts
      end
      # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

      def append_template_literal(parts, literal, location)
        literal_value = normalize_template_literal(literal)
        parts << AST::StringLiteral.new(value: literal_value, location: location)
      end

      # :reek:UtilityFunction
      def normalize_template_literal(literal)
        literal.tr(Lexer::TEMPLATE_ESCAPE, "{")
      end

      # :reek:TooManyStatements
      # :reek:FeatureEnvy
      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
      def find_template_expression_end(text, start_index)
        depth = 0
        index = start_index
        in_string = nil
        escaped = false

        while index < text.length
          char = text[index]
          if in_string
            if escaped
              escaped = false
            elsif in_string == "\"" && char == "\\"
              escaped = true
            elsif char == in_string
              in_string = nil
            end
            index += 1
            next
          end

          if char && ["\"", "`"].include?(char)
            in_string = char
            index += 1
            next
          end

          if char == "{"
            depth += 1
          elsif char == "}"
            return index if depth.zero?

            depth -= 1
          end

          index += 1
        end

        parse_error("Unterminated template expression.")
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
    end
    # rubocop:enable Metrics/ClassLength
  end
end
