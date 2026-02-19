# frozen_string_literal: true

require_relative "../ast"
require_relative "../builtins/registry"
require_relative "../call_name"
require_relative "../errors"
require_relative "../value"

module Ruby
  module Rego
    module WithModifiers
      # Resolves builtin replacement entries for `with` builtin overrides.
      # :reek:DataClump
      class WithModifierBuiltinResolver
        # @param registry [Builtins::BuiltinRegistry, Builtins::BuiltinRegistryOverlay]
        # @param environment [Environment]
        # @param expression_evaluator [Evaluator::ExpressionEvaluator]
        # @param location [Location, nil]
        def initialize(registry:, environment:, expression_evaluator:, location:)
          @registry = registry
          @environment = environment
          @expression_evaluator = expression_evaluator
          @location = location
        end

        # @param function_name [String]
        # @return [Builtins::BuiltinRegistry::Entry]
        def target_entry(function_name)
          return registry.entry_for(function_name) if registry.registered?(function_name)
          return function_entry(function_name) if function_defined?(function_name)

          raise EvaluationError.new("Undefined built-in function: #{function_name}", rule: nil, location: location)
        end

        # @param value [Object]
        # @return [Array]
        def replacement_entry(value)
          function_name = replacement_function_name(value)
          return function_replacement_entry(function_name) if function_name && function_replacement?(function_name)

          ensure_safe_replacement_variable(value, function_name)
          value_replacement_entry(value)
        end

        private

        attr_reader :registry, :environment, :expression_evaluator, :location

        # :reek:UtilityFunction
        def replacement_function_name(value)
          return value.name if value.is_a?(AST::Variable)
          return CallName.call_name(value) if value.is_a?(AST::Reference)

          nil
        end

        # :reek:UtilityFunction
        def function_replacement?(function_name)
          return false unless function_name

          function_target?(function_name)
        end

        # :reek:FeatureEnvy
        def function_replacement_entry(function_name)
          target = target_entry(function_name)
          [target.arity, target.handler, true]
        end

        def ensure_safe_replacement_variable(value, function_name)
          return unless value.is_a?(AST::Variable) && function_name
          return if expression_evaluator.variable_known?(function_name)

          raise EvaluationError.new(
            "Unsafe with replacement variable: #{function_name}",
            rule: nil,
            location: location
          )
        end

        def value_replacement_entry(value)
          replacement = resolved_replacement_value(value)
          handler = lambda do |*_args|
            replacement
          end
          [0, handler, false]
        end

        # :reek:UtilityFunction
        def function_target?(function_name)
          registry.registered?(function_name) || function_defined?(function_name)
        end

        # :reek:UtilityFunction
        def function_defined?(function_name)
          empty_rules = [] # @type var empty_rules: Array[AST::Rule]
          rules = environment.rules.fetch(function_name.to_s) { empty_rules }
          rules.any?(&:function?)
        end

        def function_entry(function_name)
          function_rule = function_rule_for(function_name)
          arity = Array(function_rule.head[:args]).length
          Builtins::BuiltinRegistry::Entry.new(
            name: function_name,
            arity: arity,
            handler: function_handler(function_name)
          )
        end

        def function_rule_for(function_name)
          function_rule = environment.rules.fetch(function_name.to_s) { [] }.find(&:function?)
          return function_rule if function_rule

          raise EvaluationError.new(
            "With modifier expects a builtin function name",
            rule: nil,
            location: location
          )
        end

        def function_handler(function_name)
          lambda do |*args|
            expression_evaluator.evaluate_user_function(function_name, args)
          end
        end

        def resolved_replacement_value(value)
          unwrap_resolved_value(expression_evaluator.evaluate(value))
        end

        # :reek:UtilityFunction
        def unwrap_resolved_value(resolved)
          resolved.is_a?(Value) ? resolved.to_ruby : resolved
        end
      end

      # Temporarily replaces a builtin with another builtin implementation.
      # :reek:DataClump
      class WithModifierBuiltinOverride
        # @param name [String]
        # @param value [Object]
        # @param expression_evaluator [Evaluator::ExpressionEvaluator]
        # @param location [Location, nil]
        def initialize(name:, value:, expression_evaluator:, location: nil)
          @name = name.to_s
          @value = value
          @expression_evaluator = expression_evaluator
          @location = location
        end

        # @yieldparam environment [Environment]
        # @return [Object]
        def apply(environment, &block)
          block ||= ->(_env) {}
          registry = environment.builtin_registry
          resolver = WithModifierBuiltinResolver.new(
            registry: registry,
            environment: environment,
            expression_evaluator: expression_evaluator,
            location: location
          )
          override_registry = registry.with_override(name, override_entry(resolver))
          environment.with_builtin_registry(override_registry, &block)
        end

        private

        attr_reader :name, :value, :expression_evaluator, :location

        def override_entry(resolver)
          original = resolver.target_entry(name)
          replacement_arity, replacement_handler, function_replacement = resolver.replacement_entry(value)
          ensure_matching_arity(original.arity, replacement_arity) if function_replacement
          arity = function_replacement ? replacement_arity : original.arity
          Builtins::BuiltinRegistry::Entry.new(name: name, arity: arity, handler: replacement_handler)
        end

        def ensure_matching_arity(expected, actual)
          expected_list = normalize_arity_list(expected)
          actual_list = normalize_arity_list(actual)
          return if expected_list.sort == actual_list.sort

          raise EvaluationError.new(
            "With modifier function arity mismatch",
            rule: nil,
            location: location
          )
        end

        # :reek:UtilityFunction
        def normalize_arity_list(arity)
          arity.is_a?(Array) ? arity : [arity]
        end
      end
    end
  end
end
