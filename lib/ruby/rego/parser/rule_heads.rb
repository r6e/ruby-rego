# frozen_string_literal: true

module Ruby
  module Rego
    # Rule-head parsing: complete/contains/function/partial-object heads and head paths.
    # :reek:DataClump
    class Parser
      private

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

      # :reek:LongParameterList
      # :reek:UtilityFunction
      def build_rule_head(type, name, name_token, **attrs)
        { type: type, name: name, location: name_token.location }.merge(attrs)
      end

      def apply_rule_head_path(head, segments, name_token)
        return head if segments.empty?
        return nested_rule_head(head, segments, name_token) if head[:type] == :complete

        parse_error("Rule head references require complete rule definitions.")
      end

      def nested_rule_head(head, segments, name_token)
        return rule_head_path_builder(head, segments, name_token).call if segments.any?

        raise ParserError.from_position(
          "Expected rule head segments.",
          position: rule_head_location(name_token),
          context: nil
        )
      end

      def rule_head_path_builder(head, segments, name_token)
        RuleHeadPathBuilder.new(head: head, segments: segments, location: rule_head_location(name_token))
      end

      def rule_head_location(name_token)
        name_token.location || current_token.location || Location.new(
          line: 1,
          column: 1,
          offset: nil,
          length: nil
        )
      end

      def bracket_expression_followed_by_path?
        closing_index = matching_bracket_index(current_index)
        return false unless closing_index

        next_token = next_non_newline_token(closing_index + 1)
        return false unless next_token

        [TokenType::DOT, TokenType::LBRACKET].include?(next_token.type)
      end

      def matching_bracket_index(start_index)
        bracket_matcher.matching_index(start_index)
      end

      def next_non_newline_token(start_index)
        index = start_index
        loop do
          token = safe_token_at(index)
          return token unless [TokenType::NEWLINE, TokenType::COMMENT].include?(token.type)

          index += 1
        end
      end

      def bracket_matcher
        @bracket_matcher ||= BracketMatcher.new(token_provider: ->(index) { safe_token_at(index) })
      end
    end
  end
end
