# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Dispatches expression evaluation for primitive and AST nodes.
      class ExpressionDispatch
        # @param primitive_types [Array<Class>]
        # @param node_evaluators [Array<Array<Class, Proc>>]
        def initialize(primitive_types:, node_evaluators:)
          @primitive_types = primitive_types
          @node_evaluators = node_evaluators
          @handler_cache = {} # @type var handler_cache: Hash[Class, Proc?]
        end

        # @param node [Object]
        # @return [Value, nil]
        def primitive_value(node)
          return Value.from_ruby(node) if primitive_types.any? { |klass| node.is_a?(klass) }

          nil
        end

        # @param node [Object]
        # @param evaluator [ExpressionEvaluator]
        # @return [Value, nil]
        def dispatch_node(node, evaluator)
          handler = handler_for(node)
          handler&.call(node, evaluator)
        end

        private

        attr_reader :primitive_types, :node_evaluators, :handler_cache

        def handler_for(node)
          node_class = node.class
          return handler_cache[node_class] if handler_cache.key?(node_class)

          handler_cache[node_class] = node_evaluators.find { |klass, _| node.is_a?(klass) }&.last
        end
      end
    end
  end
end
