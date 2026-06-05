# frozen_string_literal: true

module Ruby
  module Rego
    # Rule value/body parsing: head args/keys, braced and empty bodies, else clauses.
    class Parser
      private

      def parse_rule_head_path_segment
        consume(TokenType::LBRACKET, "Expected '[' after rule name.")
        consume_newlines
        segment = parse_expression
        consume_newlines
        consume(TokenType::RBRACKET, "Expected ']' after rule path segment.")
        segment
      end

      def parse_rule_head_args
        parse_parenthesized_expression_list(
          open_message: "Expected '(' after rule name.",
          close_message: "Expected ')' after rule arguments."
        )
      end

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
        else_clause = parse_else_clause_if_present

        { value: value, body: body, location: keyword.location, else_clause: else_clause }
      end
    end
  end
end
