# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Variable, reference, literal, and call node evaluation.
      class ExpressionEvaluator
        private

        def evaluate_variable(node)
          name = node.name
          return UndefinedValue.new if name == "_"

          resolve_variable_name(name)
        end

        def resolve_variable_name(name)
          resolve_reference_variable_key(name)
        end

        def resolve_reference_variable_key(name)
          resolved = environment.lookup(name)
          return resolved unless resolved.is_a?(UndefinedValue)
          return resolved if environment.local_bound?(name)

          resolve_import_or_rule(name, resolved)
        end

        def resolve_import_or_rule(name, fallback)
          reference_resolver.resolve_import_variable(name) ||
            reference_resolver.resolve_rule_variable(name) ||
            fallback
        end

        def evaluate_reference(node)
          reference_resolver.resolve(node)
        end

        def evaluate_array_literal(node)
          elements = node.elements.map { |element| evaluate(element) }
          ArrayValue.new(elements)
        end

        def evaluate_object_literal(node)
          object_literal_evaluator.evaluate(node)
        end

        def evaluate_set_literal(node)
          elements = node.elements.map { |element| evaluate(element) }
          SetValue.new(elements)
        end

        # :reek:TooManyStatements
        def evaluate_call(node)
          name_node = node.name
          name = self.class.call_name(name_node)
          return UndefinedValue.new unless name

          args = node.args.map { |arg| evaluate(arg) }
          return UndefinedValue.new if args.any?(&:undefined?)

          call_named_function(name, name_node, args)
        end

        def evaluate_user_function(name, args)
          return UndefinedValue.new unless query_evaluator

          query_evaluator.evaluate_function_call(name, args)
        end
        public :evaluate_user_function

        def variable_known?(name)
          variable_name = name.to_s
          return false if wildcard_variable_name?(variable_name)
          return true if locally_resolved_variable?(variable_name)

          imported_or_rule_variable?(variable_name)
        end
        public :variable_known?

        # :reek:UtilityFunction
        def wildcard_variable_name?(name)
          name == "_"
        end

        def locally_resolved_variable?(name)
          resolved = environment.lookup(name)
          !resolved.is_a?(UndefinedValue) || environment.local_bound?(name)
        end

        def imported_or_rule_variable?(name)
          !!(reference_resolver.resolve_import_variable(name) ||
            reference_resolver.resolve_rule_variable(name))
        end

        def evaluate_template_string(node)
          rendered = node.parts.map do |part|
            next part.value if part.is_a?(AST::StringLiteral)

            format_template_value(evaluate(part))
          end.join
          StringValue.new(rendered)
        end

        def call_named_function(name, name_node, args)
          registry = environment.builtin_registry
          return registry.call(name, args) if registry.registered?(name)

          function_name = function_name_for_call(name_node, name)
          evaluate_user_function(function_name, args)
        end

        def function_name_for_call(name_node, fallback_name)
          return fallback_name unless name_node.is_a?(AST::Reference)

          reference_resolver.function_reference_name(name_node) || fallback_name
        end
      end
    end
  end
end
