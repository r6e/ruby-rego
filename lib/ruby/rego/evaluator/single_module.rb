# frozen_string_literal: true

module Ruby
  module Rego
    # Evaluates compiled Rego modules against input and data.
    # :reek:InstanceVariableAssumption
    class Evaluator
      # Single-module evaluation: evaluator wiring, rule evaluation, and query dispatch.

      private

      def build_evaluators(rules_by_name, package_path)
        rule_value_provider = RuleValueProvider.new(
          rules_by_name: rules_by_name,
          memoization: environment.memoization
        )
        expression_evaluator = build_expression_evaluator(rule_value_provider, package_path)
        rule_evaluator = build_rule_evaluator(expression_evaluator, rule_value_provider)
        expression_evaluator.attach_query_evaluator(rule_evaluator)
        [expression_evaluator, rule_evaluator]
      end

      def build_expression_evaluator(rule_value_provider, package_path)
        ExpressionEvaluator.new(
          environment: @environment,
          reference_resolver: ReferenceResolver.new(
            environment: @environment,
            package_path: package_path,
            rule_value_provider: rule_value_provider,
            imports: compiled_module.imports,
            memoization: environment.memoization
          )
        )
      end

      def build_rule_evaluator(expression_evaluator, rule_value_provider)
        RuleEvaluator.new(
          environment: @environment,
          expression_evaluator: expression_evaluator
        ).tap { |evaluator| rule_value_provider.attach(evaluator) }
      end

      def evaluate_rules
        initial_results = {} # @type var initial_results: Hash[String, Value]
        environment.rules.each_with_object(initial_results) do |(name, rules), results|
          include_rule_result(results, name, rules)
        end
      end

      def include_rule_result(results, name, rules)
        value = rule_evaluator.evaluate_group(rules)
        results[name] = value unless value.is_a?(UndefinedValue)
      end

      def evaluate_query(query)
        node = QueryNodeBuilder.new(query).build
        bindings = bindings_for_query(node)
        value = expression_evaluator.evaluate(node)
        [value, bindings]
      end

      def bindings_for_query(node)
        expression_evaluator.eval_with_unification(node, environment).first || {}
      end

      def eval_node(node)
        expression_evaluator.evaluate(node)
      end
    end
  end
end
