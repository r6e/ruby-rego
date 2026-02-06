# frozen_string_literal: true

require_relative "with_modifier_context"

module Ruby
  module Rego
    # Applies `with` modifiers to a temporary environment.
    class WithModifier
      # @param target [Object]
      # @param value [Object]
      def initialize(target:, value:)
        @target = target
        @value = value
      end

      # @return [Object]
      attr_reader :target

      # @return [Object]
      attr_reader :value

      # @param environment [Environment]
      # @param expression_evaluator [Evaluator::ExpressionEvaluator]
      # @yieldparam environment [Environment]
      # @return [Object]
      def with_environment(environment, expression_evaluator, &)
        WithModifierContext.new(
          modifier: self,
          environment: environment,
          expression_evaluator: expression_evaluator
        ).apply(&)
      end
    end
  end
end
