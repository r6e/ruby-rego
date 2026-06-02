# frozen_string_literal: true

require_relative "ast"
require_relative "environment"
require_relative "errors"
require_relative "result"
require_relative "value"
require_relative "unifier"
require_relative "compiled_module"
require_relative "compiler"
require_relative "evaluator/operator_evaluator"
require_relative "evaluator/assignment_support"
require_relative "evaluator/binding_helpers"
require_relative "evaluator/expression_dispatch"
require_relative "evaluator/object_literal_evaluator"
require_relative "evaluator/comprehension_evaluator"
require_relative "evaluator/rule_value_provider"
require_relative "evaluator/reference_resolver"
require_relative "evaluator/module_context_registry"
require_relative "evaluator/reference_key_resolver"
require_relative "evaluator/expression_evaluator"
require_relative "evaluator/variable_collector"
require_relative "evaluator/rule_evaluator"
require_relative "evaluator/query_node_builder"
require_relative "with_modifiers/with_modifier"
require_relative "with_modifiers/with_modifier_applier"

module Ruby
  module Rego
    # Evaluates compiled Rego modules against input and data.
    # rubocop:disable Metrics/ClassLength
    class Evaluator
      # Builds an evaluator with a preconfigured environment.
      #
      # @param compiled_module [#rules_by_name, #package_path] compiled module
      # @param environment [Environment] preconfigured environment
      # @return [Evaluator]
      def self.from_environment(compiled_module, environment)
        evaluator = allocate
        evaluator.send(:initialize_with_environment, compiled_module, environment)
        evaluator
      end

      # Build an evaluator directly from an AST module.
      #
      # @param ast_module [AST::Module] parsed module
      # @param options [Hash] evaluator options (input, data, compiler)
      # @return [Evaluator] evaluator instance
      def self.from_ast(ast_module, options = {})
        default_input = {} # @type var default_input: Hash[untyped, untyped]
        default_data = {} # @type var default_data: Hash[untyped, untyped]
        options = { input: default_input, data: default_data, compiler: Compiler.new }.merge(options)
        new(options[:compiler].compile(ast_module), input: options[:input], data: options[:data])
      end

      # Build an evaluator over a compiled policy set.
      #
      # @param policy_set [CompiledPolicySet]
      # @param input [Object] input document
      # @param data [Object] data document
      # @return [Evaluator]
      def self.for_policy_set(policy_set, input: {}, data: {})
        evaluator = allocate
        evaluator.send(:initialize_with_policy_set, policy_set, input: input, data: data)
        evaluator
      end

      # Create an evaluator for a compiled module.
      #
      # @param compiled_module [#rules_by_name, #package_path] compiled module
      # @param input [Object] input document
      # @param data [Object] data document
      def initialize(compiled_module, input: {}, data: {})
        @policy_set = nil
        @module_contexts = nil
        @compiled_module = compiled_module
        rules_by_name = compiled_module.rules_by_name
        package_path = compiled_module.package_path
        @environment = Environment.new(input: input, data: data, rules: rules_by_name)
        @expression_evaluator, @rule_evaluator = build_evaluators(rules_by_name, package_path)
      end

      # The compiled module being evaluated.
      #
      # @return [#rules_by_name, #package_path]
      attr_reader :compiled_module

      # The environment used to evaluate expressions and rules.
      #
      # @return [Environment]
      attr_reader :environment

      # Evaluate either a query path or all rules.
      #
      # @param query [Object, nil] query path (e.g. "data.package.rule")
      # @return [Result, nil] evaluation result, or nil when a query is undefined
      def evaluate(query = nil)
        environment.memoization.reset!
        return evaluate_policy_set(query) if policy_set

        value, bindings = query ? evaluate_query(query) : [evaluate_rules, nil]
        return nil if query && value.is_a?(UndefinedValue)

        ResultBuilder.new(value, bindings).build
      end

      private

      attr_reader :policy_set, :module_contexts, :expression_evaluator, :rule_evaluator

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

      def initialize_with_policy_set(policy_set, input:, data:)
        @policy_set = policy_set
        @compiled_module = nil
        @environment = Environment.new(input: input, data: data, rules: {})
        @module_contexts = build_module_contexts(policy_set)
        attach_module_registry(@module_contexts)
        primary = @module_contexts.first
        @expression_evaluator = primary&.fetch(:expression_evaluator)
        @rule_evaluator = primary&.fetch(:rule_evaluator)
      end
      private :initialize_with_policy_set

      def build_module_contexts(policy_set)
        policy_set.modules.map { |mod| build_module_context(mod) }
      end

      def build_module_context(mod)
        package_key = mod.package_path.join(".")
        rule_value_provider = build_module_rule_value_provider(mod, package_key)
        reference_resolver = build_module_reference_resolver(mod, rule_value_provider)
        expression_evaluator, rule_evaluator = wire_evaluators(reference_resolver, rule_value_provider)
        {
          module: mod, package_key: package_key, reference_resolver: reference_resolver,
          expression_evaluator: expression_evaluator, rule_evaluator: rule_evaluator
        }
      end

      def build_module_rule_value_provider(mod, package_key)
        RuleValueProvider.new(
          rules_by_name: mod.rules_by_name,
          memoization: environment.memoization,
          package_key: package_key
        )
      end

      def build_module_reference_resolver(mod, rule_value_provider)
        ReferenceResolver.new(
          environment: @environment,
          package_path: mod.package_path,
          rule_value_provider: rule_value_provider,
          imports: mod.imports,
          memoization: environment.memoization
        )
      end

      def wire_evaluators(reference_resolver, rule_value_provider)
        expression_evaluator = ExpressionEvaluator.new(
          environment: @environment, reference_resolver: reference_resolver
        )
        rule_evaluator = RuleEvaluator.new(
          environment: @environment, expression_evaluator: expression_evaluator
        )
        rule_value_provider.attach(rule_evaluator)
        expression_evaluator.attach_query_evaluator(rule_evaluator)
        [expression_evaluator, rule_evaluator]
      end

      def attach_module_registry(contexts)
        resolvers_by_key = contexts.to_h do |context|
          [context.fetch(:package_key), context.fetch(:reference_resolver)]
        end
        registry = ModuleContextRegistry.new(resolvers_by_key)
        contexts.each { |context| context.fetch(:reference_resolver).attach_module_resolver(registry) }
      end

      def evaluate_policy_set(query)
        return evaluate_policy_set_query(query) if query

        value = evaluate_policy_set_rules
        ResultBuilder.new(value, nil).build
      end

      def evaluate_policy_set_query(query)
        context = context_for_query(query)
        return nil unless context

        evaluator = context.fetch(:expression_evaluator)
        node = QueryNodeBuilder.new(query).build
        bindings = evaluator.eval_with_unification(node, environment).first || {}
        value = evaluator.evaluate(node)
        return nil if value.is_a?(UndefinedValue)

        ResultBuilder.new(value, bindings).build
      end

      def context_for_query(query)
        keys = query.to_s.split(".")
        keys = keys[1..] || [] if keys.first == "data"
        mod = policy_set.module_for(keys)
        return context_by_module(mod) if mod

        module_contexts.first
      end

      def context_by_module(mod)
        module_contexts.find { |context| context.fetch(:module).equal?(mod) }
      end

      def evaluate_policy_set_rules
        tree = {} # @type var tree: Hash[String, untyped]
        module_contexts.each do |context|
          rules_value = evaluate_module_rules(context)
          next if rules_value.empty?

          assign_package_subtree(tree, context.fetch(:module).package_path, rules_value)
        end
        Value.from_ruby(tree)
      end

      def evaluate_module_rules(context)
        evaluator = context.fetch(:rule_evaluator)
        mod = context.fetch(:module)
        results = {} # @type var results: Hash[String, untyped]
        mod.rules_by_name.each do |name, rules|
          value = evaluator.evaluate_group(rules)
          results[name] = value.to_ruby unless value.is_a?(UndefinedValue)
        end
        results
      end

      def assign_package_subtree(tree, package_path, rules_value)
        node = tree
        package_path[0...-1].each do |segment|
          node = (node[segment] ||= {})
        end
        node[package_path.last] = rules_value
      end

      def initialize_with_environment(compiled_module, environment)
        @policy_set = nil
        @module_contexts = nil
        @compiled_module = compiled_module
        rules_by_name = compiled_module.rules_by_name
        package_path = compiled_module.package_path
        @environment = environment
        @expression_evaluator, @rule_evaluator = build_evaluators(rules_by_name, package_path)
      end
      private :initialize_with_environment
    end
    # rubocop:enable Metrics/ClassLength

    # Builds result objects from evaluation outputs.
    class ResultBuilder
      def initialize(value, bindings)
        @value = value
        @bindings = bindings
      end

      def build
        success = !value.is_a?(UndefinedValue)
        return Result.new(value: value, success: success) unless bindings

        Result.new(value: value, success: success, bindings: bindings)
      end

      private

      attr_reader :bindings, :value
    end
  end
end
