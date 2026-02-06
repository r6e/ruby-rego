# frozen_string_literal: true

module Ruby
  module Rego
    # Parsing helpers for references and identifiers.
    class Parser
      private

      def parse_reference(base)
        reference_base, path = Helpers.normalize_reference_base(base)
        parse_reference_path(path)
        AST::Reference.new(base: reference_base, path: path, location: base.location)
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
    end
  end
end
