# frozen_string_literal: true

module Ruby
  module Rego
    # Parsing helpers for collection literals and comprehensions.
    # :reek:TooManyMethods
    # :reek:RepeatedConditional
    # :reek:DataClump
    # rubocop:disable Metrics/ClassLength
    class Parser
      private

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
      def parse_braced_literal
        start = consume(TokenType::LBRACE)
        consume_newlines
        return empty_object_literal(start) if rbrace_token?

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
        parse_comprehension(
          start_token,
          term,
          TokenType::RBRACKET,
          ["Expected '|' after array term.", "Expected ']' after array comprehension."],
          AST::ArrayComprehension
        )
      end

      def parse_object_comprehension(start_token, key, value)
        parse_comprehension(
          start_token,
          [key, value],
          TokenType::RBRACE,
          ["Expected '|' after object term.", "Expected '}' after object comprehension."],
          AST::ObjectComprehension
        )
      end

      def parse_set_comprehension(start_token, term)
        parse_comprehension(
          start_token,
          term,
          TokenType::RBRACE,
          ["Expected '|' after set term.", "Expected '}' after set comprehension."],
          AST::SetComprehension
        )
      end

      # :reek:LongParameterList
      def parse_comprehension(start_token, term, end_token, messages, node_class)
        pipe_message, end_message = messages
        consume(TokenType::PIPE, pipe_message)
        body = parse_query(end_token, newline_delimiter: true)
        consume(end_token, end_message)
        node_class.new(term: term, body: body, location: start_token.location)
      end

      def empty_set?(first_element)
        rbrace_token? && !first_element
      end

      def empty_object_literal(start_token)
        advance
        AST::ObjectLiteral.new(pairs: [], location: start_token.location)
      end

      def empty_set_literal(start_token)
        advance
        AST::SetLiteral.new(elements: [], location: start_token.location)
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
end
