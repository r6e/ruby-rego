# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Rule-body value extraction: body solutions, else clauses, and value-with-body context.
      # :reek:DataClump
      class RuleEvaluator
        private

        def evaluate_rule_value(head)
          case head[:type]
          when :complete, :function
            evaluate_complete_rule_value(head)
          when :partial_set
            expression_evaluator.evaluate(head[:term])
          else
            UndefinedValue.new
          end
        end

        def some_decl_truthy?(literal)
          each_some_solution(literal).any?
        end

        # :reek:TooManyStatements
        # rubocop:disable Metrics/MethodLength
        def rule_body_values(rule, initial_bindings = {})
          environment.push_scope
          values = environment.with_bindings(initial_bindings) do
            eval_rule_body(rule.body, environment).filter_map do |bindings|
              environment.with_bindings(bindings) do
                value = evaluate_rule_value(rule.head)
                value unless value.is_a?(UndefinedValue)
              end
            end
          end
          values
        ensure
          environment.pop_scope
        end
        # rubocop:enable Metrics/MethodLength

        # :reek:TooManyStatements
        # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
        def rule_body_pairs(rule)
          environment.push_scope
          values = eval_rule_body(rule.body, environment).filter_map do |bindings|
            environment.with_bindings(bindings) do
              pair = evaluate_partial_object_value(rule.head)
              next unless pair.is_a?(Array)

              nested_flag = rule.head.is_a?(Hash) && rule.head[:nested] ? true : false
              [pair[0], pair[1], nested_flag]
            end
          end
          values
        ensure
          environment.pop_scope
        end
        # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

        def complete_rule_value_with_else(rule)
          values = rule_body_values(rule)
          resolved = resolve_conflicts(values, rule.name)
          return resolved if resolved

          else_clause_value(rule, rule.else_clause)
        end

        def else_clause_value(rule, clause)
          return UndefinedValue.new unless clause

          values = evaluate_clause_value(rule, clause, empty_bindings)
          resolved = resolve_conflicts(values, rule.name)
          return resolved if resolved

          else_clause_value(rule, clause[:else_clause])
        end

        def evaluate_value_with_body(context)
          environment.push_scope
          values = values_for_body_context(context)
          values
        ensure
          environment.pop_scope
        end

        def values_for_body_context(context)
          environment.with_bindings(context.initial_bindings) do
            eval_rule_body(context.body, environment).filter_map do |bindings|
              environment.with_bindings(bindings) { evaluate_value_node(context.rule, context.value_node) }
            end
          end
        end

        def evaluate_value_node(rule, value_node)
          value = evaluate_complete_rule_value(rule.head, value_node)
          value unless value.is_a?(UndefinedValue)
        end
      end
    end
  end
end
