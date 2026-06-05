# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Evaluates rule bodies and heads.
      # :reek:TooManyMethods
      # :reek:DataClump
      class RuleEvaluator
        # Bundles query evaluation state to minimize parameter passing.
        QueryContext = Struct.new(:literals, :env)
        # Bundles value evaluation parameters for else/default handling.
        ValueEvaluationContext = Struct.new(:body, :rule, :value_node, :initial_bindings)
        # Bundles modifier evaluation state.
        class ModifierContext
          # @param expression [Object]
          # @param env [Environment]
          # @param bound_vars [Array<String>]
          def initialize(expression:, env:, bound_vars:)
            @expression = expression
            @env = env
            @bound_vars = bound_vars
          end

          # @return [Object]
          attr_reader :expression

          # @return [Environment]
          attr_reader :env

          # @return [Array<String>]
          attr_reader :bound_vars
        end

        # @param environment [Environment]
        # @param expression_evaluator [ExpressionEvaluator]
        # @param rules [Hash{String => Array<AST::Rule>}, nil] function lookup table (defaults to environment.rules)
        # @param package_key [String] namespaces the function-value cache
        # :reek:LongParameterList
        def initialize(environment:, expression_evaluator:, rules: nil, package_key: "")
          @environment = environment
          @expression_evaluator = expression_evaluator
          @unifier = Unifier.new
          @rules = rules
          @package_key = package_key
        end

        # @param rules [Array<AST::Rule>]
        # @return [Value]
        def evaluate_group(rules)
          return UndefinedValue.new if rules.empty?

          first_rule = rules.first
          return UndefinedValue.new if first_rule.function?
          return evaluate_partial_set_rules(rules) if first_rule.partial_set?
          return evaluate_partial_object_rules(rules) if first_rule.partial_object?

          evaluate_complete_rules(rules)
        end

        # @param name [String]
        # @param args [Array<Value>]
        # @return [Value]
        def evaluate_function_call(name, args)
          cache = memoization&.context&.function_values
          if cache
            key = [package_key, name.to_s, args]
            return cache[key] if cache.key?(key)

            cache[key] = evaluate_function_call_uncached(name, args)
            return cache[key]
          end

          evaluate_function_call_uncached(name, args)
        end

        def evaluate_function_call_uncached(name, args)
          rules = function_rule_table.fetch(name.to_s) { [] }
          function_rules = rules.select(&:function?)
          return UndefinedValue.new if function_rules.empty?

          value = evaluate_function_rules(function_rules, args)
          return value unless value.is_a?(Array)

          resolved = resolve_conflicts(value, name)
          resolved || UndefinedValue.new
        end

        def function_rule_table
          @rules || environment.rules
        end

        # @param rule [AST::Rule]
        # @return [Value, Array]
        # :reek:FeatureEnvy
        def evaluate_rule(rule)
          values = rule_body_values(rule)
          resolved = resolve_conflicts(values, rule.name)
          resolved || UndefinedValue.new
        end

        # @param literals [Array<Object>]
        # @param env [Environment]
        # @return [Enumerator]
        # @api private
        def query_solutions(literals, env = environment)
          eval_query(literals, env)
        end

        private

        attr_reader :environment, :expression_evaluator, :unifier, :package_key

        def memoization
          environment.memoization
        end
      end
    end
  end
end

require_relative "rule_evaluator/bindings"
require_relative "rule_evaluator/query"
require_relative "rule_evaluator/partial_rules"
require_relative "rule_evaluator/rule_values"
require_relative "rule_evaluator/rule_bodies"
require_relative "rule_evaluator/function_rules"
