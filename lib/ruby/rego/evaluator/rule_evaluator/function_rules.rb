# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Function-rule evaluation: argument unification and else clauses.
      # :reek:DataClump
      class RuleEvaluator
        private

        def evaluate_function_rules(rules, args)
          # @type var values: Array[Value]
          values = []
          rules.reject(&:default_value).each do |rule|
            values.concat(function_rule_values(rule, args))
          end

          return values unless values.empty?

          default_rule = rules.find(&:default_value)
          return [] unless default_rule

          function_rule_values(default_rule, args)
        end

        # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
        def function_rule_values(rule, args)
          head_args = Array(rule.head[:args])
          return [] unless head_args.length == args.length

          # @type var binding_sets: Array[Hash[String, Value]]
          binding_sets = [{}]
          head_args.each_with_index do |pattern, index|
            # @type var next_sets: Array[Hash[String, Value]]
            next_sets = []
            binding_sets.each do |bindings|
              environment.with_bindings(bindings) do
                unifier.unify(pattern, args[index], environment).each do |new_bindings|
                  merged = merge_bindings(bindings, new_bindings)
                  next_sets << merged if merged
                end
              end
            end
            binding_sets = next_sets
          end

          binding_sets.flat_map do |bindings|
            function_values_with_else(rule, bindings)
          end
        end
        # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

        def function_values_with_else(rule, bindings)
          values = rule_body_values(rule, bindings)
          return values unless values.empty?

          function_else_values(rule, rule.else_clause, bindings)
        end

        def function_else_values(rule, clause, bindings)
          return [] unless clause

          values = evaluate_clause_value(rule, clause, bindings)
          return values unless values.empty?

          function_else_values(rule, clause[:else_clause], bindings)
        end

        def empty_bindings
          {} # @type var empty_bindings: Hash[String, Value]
        end

        def evaluate_clause_value(rule, clause, bindings)
          context = ValueEvaluationContext.new(
            body: clause[:body],
            rule: rule,
            value_node: clause[:value],
            initial_bindings: bindings
          )
          evaluate_value_with_body(context)
        end
      end
    end
  end
end
