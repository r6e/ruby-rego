# frozen_string_literal: true

module Ruby
  module Rego
    # Rule-head value builders (object-path nesting, bracket matching).
    class Parser
      # Builds nested object values for rule head segments.
      class RuleHeadPathBuilder
        # @param head [Hash]
        # @param segments [Array<AST::expression>]
        # @param location [Location]
        def initialize(head:, segments:, location:)
          @head = head
          @segments = segments
          @location = location
        end

        # @return [Hash]
        def call
          key_segment, *remaining = segments
          return head unless key_segment

          value_node = head[:value] || AST::BooleanLiteral.new(value: true, location: location)
          value_node = build_nested_value(remaining, value_node)

          head.merge(
            type: :partial_object,
            key: normalize(key_segment),
            value: value_node,
            nested: remaining.any?
          )
        end

        private

        attr_reader :head, :segments, :location

        def build_nested_value(segments, value_node)
          segments.reverse_each do |segment|
            key_node = normalize(segment) # @type var key_node: AST::expression
            value_node = AST::ObjectLiteral.new(pairs: [[key_node, value_node]], location: location)
          end
          value_node
        end

        # :reek:FeatureEnvy
        def normalize(segment)
          return segment if segment.is_a?(AST::Base)

          AST::StringLiteral.new(value: segment.to_s, location: location)
        end
      end

      # Finds matching closing brackets for rule head path segments.
      class BracketMatcher
        BRACKET_DEPTH_DELTA = {
          TokenType::LBRACKET => 1,
          TokenType::RBRACKET => -1
        }.freeze

        # @param token_provider [#call]
        def initialize(token_provider:)
          @token_provider = token_provider
        end

        # @param start_index [Integer]
        # @return [Integer, nil]
        # :reek:FeatureEnvy
        def matching_index(start_index)
          depth = 0

          loop do
            token_type = token_provider.call(start_index).type
            return nil if token_type == TokenType::EOF

            depth += BRACKET_DEPTH_DELTA.fetch(token_type, 0)
            return start_index if token_type == TokenType::RBRACKET && depth.zero?

            start_index += 1
          end
        end

        private

        attr_reader :token_provider
      end
    end
  end
end
