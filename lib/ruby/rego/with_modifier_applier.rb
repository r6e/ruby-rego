# frozen_string_literal: true

require_relative "with_modifier"

module Ruby
  module Rego
    # Applies a sequence of with modifiers around a block.
    class WithModifierApplier
      # @param modifiers [Array<AST::WithModifier>]
      # @param environment [Environment]
      # @param expression_evaluator [Evaluator::ExpressionEvaluator]
      # @yieldparam environment [Environment]
      # @return [Object]
      def self.apply(modifiers, environment, expression_evaluator, &block)
        block ||= ->(_env) {}
        return block.call(environment) if modifiers.empty?

        build_chain(modifiers, expression_evaluator, block).call(environment)
      end

      def self.build_chain(modifiers, expression_evaluator, block)
        index = modifiers.length - 1
        chain = block

        while index >= 0
          chain = wrap_modifier(modifiers[index], expression_evaluator, chain)
          index -= 1
        end

        chain
      end

      def self.wrap_modifier(modifier, expression_evaluator, block)
        lambda do |env|
          WithModifier.new(target: modifier.target, value: modifier.value).with_environment(
            env,
            expression_evaluator,
            &block
          )
        end
      end

      private_class_method :build_chain, :wrap_modifier
    end
  end
end
