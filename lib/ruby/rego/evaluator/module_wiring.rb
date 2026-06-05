# frozen_string_literal: true

module Ruby
  module Rego
    # Evaluates compiled Rego modules against input and data.
    # :reek:InstanceVariableAssumption
    class Evaluator
      # Policy-set module wiring: per-module contexts, resolvers, and evaluator wiring.

      private

      def initialize_with_policy_set(policy_set, input:, data:)
        @policy_set = policy_set
        @compiled_module = nil
        @environment = Environment.new(input: input, data: data, rules: {})
        @module_contexts = build_module_contexts(policy_set)
        attach_module_registry(@module_contexts)
        detect_package_rule_conflicts
        primary = @module_contexts.first
        @expression_evaluator = primary&.expression_evaluator
        @rule_evaluator = primary&.rule_evaluator
      end
      private :initialize_with_policy_set

      def build_module_contexts(policy_set)
        policy_set.modules.map { |mod| build_module_context(mod) }
      end

      def build_module_context(mod)
        package_key = mod.package_path.join(".")
        rule_value_provider, reference_resolver = build_module_resolvers(mod, package_key)
        expression_evaluator, rule_evaluator =
          wire_module_evaluators(mod, package_key, reference_resolver, rule_value_provider)
        ModuleContext.new(
          compiled_module: mod, package_key: package_key, reference_resolver: reference_resolver,
          expression_evaluator: expression_evaluator, rule_evaluator: rule_evaluator
        )
      end

      def build_module_resolvers(mod, package_key)
        rule_value_provider = RuleValueProvider.new(
          rules_by_name: mod.rules_by_name, memoization: environment.memoization, package_key: package_key
        )
        reference_resolver = ReferenceResolver.new(
          environment: @environment, package_path: mod.package_path, rule_value_provider: rule_value_provider,
          imports: mod.imports, memoization: environment.memoization
        )
        [rule_value_provider, reference_resolver]
      end

      # :reek:LongParameterList
      def wire_module_evaluators(mod, package_key, reference_resolver, rule_value_provider)
        expression_evaluator = ExpressionEvaluator.new(
          environment: @environment, reference_resolver: reference_resolver
        )
        rule_evaluator = RuleEvaluator.new(
          environment: @environment, expression_evaluator: expression_evaluator,
          rules: mod.rules_by_name, package_key: package_key
        )
        rule_value_provider.attach(rule_evaluator)
        expression_evaluator.attach_query_evaluator(rule_evaluator)
        [expression_evaluator, rule_evaluator]
      end

      def attach_module_registry(contexts)
        resolvers_by_key = contexts.to_h do |context|
          [context.package_key, context.reference_resolver]
        end
        registry = ModuleContextRegistry.new(resolvers_by_key)
        contexts.each { |context| context.reference_resolver.attach_module_resolver(registry) }
      end
    end
  end
end
