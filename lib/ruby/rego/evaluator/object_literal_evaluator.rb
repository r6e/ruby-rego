# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Evaluates object literal nodes.
      class ObjectLiteralEvaluator
        # @param expression_evaluator [ExpressionEvaluator]
        def initialize(expression_evaluator:)
          @expression_evaluator = expression_evaluator
        end

        # @param node [AST::ObjectLiteral]
        # @return [Value]
        def evaluate(node)
          pairs = build_pairs(node)
          return pairs if pairs.is_a?(UndefinedValue)

          ObjectValue.new(pairs)
        end

        private

        attr_reader :expression_evaluator

        def build_pairs(node)
          pairs = node.pairs.map do |(key_node, value_node)|
            pair = resolve_pair(key_node, value_node)
            return UndefinedValue.new if pair.is_a?(UndefinedValue)

            pair
          end
          pairs.to_h
        end

        def evaluate_key(key_node)
          expression_evaluator.evaluate(key_node).object_key
        end

        def resolve_pair(key_node, value_node)
          key = evaluate_key(key_node)
          return UndefinedValue.new if key.is_a?(UndefinedValue)

          value = expression_evaluator.evaluate(value_node)
          return UndefinedValue.new if value.is_a?(UndefinedValue)

          [key, value]
        end
      end
    end
  end
end
