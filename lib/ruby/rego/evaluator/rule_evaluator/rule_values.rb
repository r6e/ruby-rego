# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Complete-rule value entry, body-success predicates, and conflict resolution.
      class RuleEvaluator
        private

        def evaluate_complete_rules(rules)
          values = rules.reject(&:default_value).map do |rule|
            complete_rule_value_with_else(rule)
          end.reject(&:undefined?)

          resolved = resolve_conflicts(values, rules.first.name)
          return resolved if resolved

          default_rule = rules.find(&:default_value)
          return UndefinedValue.new unless default_rule

          expression_evaluator.evaluate(default_rule.default_value)
        end

        def evaluate_partial_object_value(head)
          key = expression_evaluator.evaluate(head[:key])
          value = expression_evaluator.evaluate(head[:value])
          return UndefinedValue.new if key.is_a?(UndefinedValue) || value.is_a?(UndefinedValue)

          [key.to_ruby, value]
        end

        def evaluate_complete_rule_value(head, value_node = nil)
          node = value_node || head[:value]
          return expression_evaluator.evaluate(node) if node

          BooleanValue.new(true)
        end

        def body_succeeds?(body)
          literals = Array(body)
          return true if literals.empty?

          eval_query(literals, environment).any?
        end

        def query_literal_truthy?(literal)
          eval_query([literal], environment).any?
        end

        def some_decl_truthy?(literal)
          each_some_solution(literal).any?
        end

        def resolve_conflicts(values, name)
          return nil if values.empty?

          unique = values.uniq
          return unique.first if unique.length == 1

          raise EvaluationError.new("Conflicting values for #{name}", rule: name)
        end
      end
    end
  end
end
