# frozen_string_literal: true

require_relative "../ast"
require_relative "../builtins/registry"
require_relative "../errors"
require_relative "../value"

module Ruby
  module Rego
    module WithModifiers
      # Temporarily replaces a builtin with another builtin implementation.
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
          registry.entry_for(name)
          override_registry = registry.with_override(name, override_entry(registry, environment))
          environment.with_builtin_registry(override_registry, &block)
        end

        private

        attr_reader :name, :value, :expression_evaluator, :location

        def override_entry(registry, environment)
          original = registry.entry_for(name)
          replacement = replacement_entry(registry, environment)
          ensure_matching_arity(original.arity, replacement.arity)
          Builtins::BuiltinRegistry::Entry.new(name: name, arity: replacement.arity, handler: replacement.handler)
        end

        def replacement_entry(registry, environment)
          replacement = replacement_name
          return registry.entry_for(replacement) if registry.registered?(replacement)

          function_entry(environment, replacement)
        end

        # rubocop:disable Metrics/MethodLength
        def function_entry(environment, function_name)
          # @type var empty_rules: Array[AST::Rule]
          empty_rules = []
          rules = environment.rules.fetch(function_name.to_s) { empty_rules }
          function_rule = rules.find(&:function?)
          unless function_rule
            raise EvaluationError.new(
              "With modifier expects a builtin function name",
              rule: nil,
              location: location
            )
          end

          arity = Array(function_rule.head[:args]).length
          handler = lambda do |*args|
            expression_evaluator.evaluate_user_function(function_name, args)
          end
          Builtins::BuiltinRegistry::Entry.new(name: function_name, arity: arity, handler: handler)
        end
        # rubocop:enable Metrics/MethodLength

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

        def replacement_name
          direct_name = direct_name_from_value
          return direct_name if direct_name

          resolved_name = resolved_name_from_value
          return resolved_name if resolved_name

          raise EvaluationError.new(
            "With modifier expects a builtin function name",
            rule: nil,
            location: location
          )
        end

        def direct_name_from_value
          return value.name if value.is_a?(AST::Variable)
          return reference_name_from_value if value.is_a?(AST::Reference)
          return value.value if value.is_a?(AST::StringLiteral)

          nil
        end

        def reference_name_from_value
          base = value.base
          return base.name if base.is_a?(AST::Variable) && value.path.empty?

          nil
        end

        def resolved_name_from_value
          resolved = expression_evaluator.evaluate(value)
          resolved_value = resolved.is_a?(Value) ? resolved.to_ruby : resolved
          resolved_value if resolved_value.is_a?(String)
        end
      end
    end
  end
end
