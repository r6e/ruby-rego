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
      # @param ast_module [AST::Module]
      # @param options [Hash]
      # @return [Evaluator]
      def self.from_ast(ast_module, options = {})
        default_input = {} # @type var default_input: Hash[untyped, untyped]
        default_data = {} # @type var default_data: Hash[untyped, untyped]
        options = { input: default_input, data: default_data, compiler: Compiler.new }.merge(options)
        new(options[:compiler].compile(ast_module), input: options[:input], data: options[:data])
      end

      # @param compiled_module [#rules_by_name, #package_path]
      # @param input [Object]
      # @param data [Object]
      def initialize(compiled_module, input: {}, data: {})
        @compiled_module = compiled_module
        rules_by_name = compiled_module.rules_by_name
        package_path = compiled_module.package_path
        @environment = Environment.new(input: input, data: data, rules: rules_by_name)
        @expression_evaluator, @rule_evaluator = build_evaluators(rules_by_name, package_path)
      end

      # @return [#rules_by_name, #package_path]
      attr_reader :compiled_module

      # @return [Environment]
      attr_reader :environment

      # @param query [Object, nil]
      # @return [Result]
      def evaluate(query = nil)
        value = query ? evaluate_query(query) : evaluate_rules
        Result.new(value: value, success: !value.is_a?(UndefinedValue))
      end

      private

      attr_reader :expression_evaluator, :rule_evaluator

      def build_evaluators(rules_by_name, package_path)
        rule_value_provider = RuleValueProvider.new(rules_by_name: rules_by_name)
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
            rule_value_provider: rule_value_provider
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
        results = {} # @type var results: Hash[String, Value]
        environment.rules.each do |name, rules|
          results[name] = rule_evaluator.evaluate_group(rules)
        end
        results
      end

      def evaluate_query(query)
        node = QueryNodeBuilder.new(query).build
        expression_evaluator.evaluate(node)
      end

      def eval_node(node)
        expression_evaluator.evaluate(node)
      end
    end
  end
end
