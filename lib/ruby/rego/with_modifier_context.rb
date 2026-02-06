# frozen_string_literal: true

require_relative "ast"
require_relative "errors"
require_relative "value"
require_relative "with_modifier_builtin_override"
require_relative "with_modifier_path_key_resolver"
require_relative "with_modifier_path_override"
require_relative "with_modifier_root_scope"

module Ruby
  module Rego
    # Applies a single with modifier in a given environment.
    class WithModifierContext
      # @param modifier [WithModifier]
      # @param environment [Environment]
      # @param expression_evaluator [Evaluator::ExpressionEvaluator]
      def initialize(modifier:, environment:, expression_evaluator:)
        @modifier = modifier
        @environment = environment
        @expression_evaluator = expression_evaluator
      end

      # @yieldparam environment [Environment]
      # @return [Object]
      def apply(&)
        return apply_reference(&) if target.is_a?(AST::Reference)
        return apply_variable(&) if target.is_a?(AST::Variable)

        raise EvaluationError.new("Unsupported with target: #{target.class}", rule: nil, location: target.location)
      end

      private

      attr_reader :modifier, :environment, :expression_evaluator

      def target
        modifier.target
      end

      def value
        modifier.value
      end

      def apply_reference(&)
        scope = reference_scope
        overridden = reference_override(scope)
        return overridden if overridden.is_a?(UndefinedValue)

        scope.with_override(overridden, &)
      end

      def reference_scope
        base = target.base
        location = target.location
        unless base.is_a?(AST::Variable)
          raise EvaluationError.new("Unsupported with target base: #{base.class}", rule: nil, location: location)
        end

        WithModifierRootScope.new(
          environment: environment,
          name: base.name,
          location: location
        )
      end

      def reference_override(scope)
        keys = reference_path_keys
        return UndefinedValue.new if keys.is_a?(UndefinedValue)

        replacement = resolved_value
        WithModifierPathOverride.new(
          base_value: scope.base_value,
          keys: keys,
          replacement: replacement,
          location: target.location
        ).apply
      end

      # :reek:TooManyStatements
      # Returns UndefinedValue when any path key is undefined to short-circuit modifier application.
      def reference_path_keys
        resolver = WithModifierPathKeyResolver.new(expression_evaluator: expression_evaluator)
        keys = target.path.map { |segment| resolver.resolve(segment) }
        undefined_key = keys.find { |key| key.is_a?(UndefinedValue) }
        undefined_key || keys
      end

      def apply_variable(&)
        name = target.name
        if WithModifierRootScope::ROOT_NAMES.include?(name)
          scope = WithModifierRootScope.new(
            environment: environment,
            name: name,
            location: target.location
          )
          return scope.with_override(resolved_value, &)
        end

        apply_builtin_override(name, &)
      end

      def apply_builtin_override(name, &)
        WithModifierBuiltinOverride.new(
          name: name,
          value: value,
          expression_evaluator: expression_evaluator,
          location: target.location
        ).apply(environment, &)
      end

      def resolved_value
        resolved = expression_evaluator.evaluate(value)
        resolved.is_a?(Value) ? resolved.to_ruby : resolved
      end
    end
  end
end
