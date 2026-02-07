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
          override_registry = registry.with_override(name, override_entry(registry))
          environment.with_builtin_registry(override_registry, &block)
        end

        private

        attr_reader :name, :value, :expression_evaluator, :location

        def override_entry(registry)
          entry = registry.entry_for(replacement_name)
          Builtins::BuiltinRegistry::Entry.new(name: name, arity: entry.arity, handler: entry.handler)
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
