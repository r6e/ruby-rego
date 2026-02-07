# frozen_string_literal: true

require_relative "../ast"
require_relative "../value"

module Ruby
  module Rego
    module WithModifiers
      # Resolves reference path segments for with modifiers.
      class WithModifierPathKeyResolver
        # @param expression_evaluator [Evaluator::ExpressionEvaluator]
        def initialize(expression_evaluator:)
          @expression_evaluator = expression_evaluator
        end

        # @param segment [Object]
        # @return [Object]
        # :reek:FeatureEnvy
        # :reek:TooManyStatements
        def resolve(segment)
          raw = segment.is_a?(AST::RefArg) ? segment.value : segment
          key = resolved_key(raw)
          return key if key.is_a?(UndefinedValue)

          key.is_a?(Symbol) ? key.to_s : key
        end

        private

        attr_reader :expression_evaluator

        # :reek:FeatureEnvy
        def resolved_key(raw)
          resolved = expression_evaluator.evaluate(raw)
          return resolved if resolved.is_a?(UndefinedValue)

          resolved.is_a?(Value) ? resolved.to_ruby : resolved
        end
      end
    end
  end
end
