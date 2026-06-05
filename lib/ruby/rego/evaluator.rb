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
require_relative "evaluator/local_shadowing"
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
    class Evaluator
      # Per-module evaluation context for the policy-set path.
      ModuleContext = Struct.new(
        :compiled_module, :package_key, :reference_resolver,
        :expression_evaluator, :rule_evaluator,
        keyword_init: true
      )

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
  end
end

require_relative "evaluator/single_module"
require_relative "evaluator/policy_set"
require_relative "evaluator/module_wiring"
require_relative "evaluator/result_builder"
