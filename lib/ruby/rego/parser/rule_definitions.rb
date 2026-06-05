# frozen_string_literal: true

module Ruby
  module Rego
    # :reek:RepeatedConditional
    # rubocop:disable Metrics/ClassLength
    # Rule-definition parsing: rule names, head segments, default/non-default values, and else clauses.
    # :reek:DataClump
    class Parser
      private

      # :reek:TooManyStatements
      def parse_rule
        default_token = consume_default_keyword
        name_token = current_token
        name, head_segments = parse_rule_name_path
        head = parse_rule_head(name, name_token)
        head = apply_rule_head_path(head, head_segments, name_token)
        head = mark_default_head(head) if default_token
        definition = parse_rule_definition(default_token, head)
        validate_rule_definition(default_token, head, definition)

        build_rule_node(name: name, head: head, name_token: name_token, definition: definition)
      end

      def consume_default_keyword
        match?(TokenType::DEFAULT) ? advance : nil
      end

      def parse_rule_name_path
        context = IdentifierContext.new(name: "rule", allowed_types: PACKAGE_PATH_TOKEN_TYPES)
        name = parse_identifier(context)
        [name, parse_rule_head_segments(context)]
      end

      def parse_rule_head_segments(context)
        segments = [] # @type var segments: Array[AST::expression]
        loop do
          break unless consume_rule_head_newlines?(segments)

          segment = parse_rule_head_segment(context, segments) or break
          segments << segment
        end
        segments
      end

      def consume_rule_head_newlines?(segments)
        return true unless segments.any? && newline_token?

        return false unless rule_head_path_continues_after_newline?

        consume_newlines
        true
      end

      def rule_head_path_continues_after_newline?
        next_token = next_non_newline_token(current_index)
        next_token && [TokenType::DOT, TokenType::LBRACKET].include?(next_token.type)
      end

      def parse_rule_head_segment(context, segments)
        return parse_dot_rule_head_segment(context) if match?(TokenType::DOT)
        return parse_bracket_rule_head_segment(segments) if match?(TokenType::LBRACKET)

        nil
      end

      def parse_dot_rule_head_segment(context)
        advance
        segment_token = current_token
        segment = parse_identifier(context)
        AST::StringLiteral.new(value: segment, location: segment_token.location)
      end

      def parse_bracket_rule_head_segment(segments)
        return parse_rule_head_path_segment if segments.any?

        return nil unless bracket_expression_followed_by_path?

        parse_rule_head_path_segment
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
    end
    # rubocop:enable Metrics/ClassLength
  end
end
