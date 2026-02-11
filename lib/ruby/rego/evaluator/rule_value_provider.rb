# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Provides evaluated rule values for data references.
      class RuleValueProvider
        # @param rules_by_name [Hash{String => Array<AST::Rule>}]
        # @param memoization [Memoization::Store, nil]
        def initialize(rules_by_name:, memoization: nil)
          @rules_by_name = rules_by_name
          @memoization = memoization
          @rule_evaluator = nil
        end

        # @param rule_evaluator [RuleEvaluator]
        # @return [void]
        def attach(rule_evaluator)
          @rule_evaluator = rule_evaluator
        end

        # @param name [String]
        # @return [Value]
        def value_for(name)
          memoization ? memoized_value_for(name) : evaluate_value_for(name)
        end

        # @param name [String]
        # @return [Boolean]
        def rule_defined?(name)
          rules_by_name.key?(name)
        end

        private

        attr_reader :memoization, :rule_evaluator, :rules_by_name

        def memoized_value_for(name)
          memo = memoization
          return evaluate_value_for(name) unless memo

          cache = memo.context.rule_values
          cache.fetch(name.to_s) { |key| cache[key] = evaluate_value_for(key) }
        end

        def evaluate_value_for(name)
          rules = rules_by_name.fetch(name) { [] } # @type var rules: Array[AST::Rule]
          return UndefinedValue.new if rules.empty?
          return UndefinedValue.new unless rule_evaluator

          rule_evaluator.evaluate_group(rules)
        end
      end
    end
  end
end
