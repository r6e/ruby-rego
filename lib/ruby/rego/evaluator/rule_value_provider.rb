# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Provides evaluated rule values for data references.
      class RuleValueProvider
        # @param rules_by_name [Hash{String => Array<AST::Rule>}]
        def initialize(rules_by_name:)
          @rules_by_name = rules_by_name
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
          rules = rules_by_name.fetch(name) { [] } # @type var rules: Array[AST::Rule]
          return UndefinedValue.new if rules.empty?
          return UndefinedValue.new unless rule_evaluator

          rule_evaluator.evaluate_group(rules)
        end

        # @param name [String]
        # @return [Boolean]
        def rule_defined?(name)
          rules_by_name.key?(name)
        end

        private

        attr_reader :rule_evaluator, :rules_by_name
      end
    end
  end
end
