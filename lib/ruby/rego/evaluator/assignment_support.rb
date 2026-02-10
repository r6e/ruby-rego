# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Shared helpers for assignment/unification logic.
      module AssignmentSupport
        private

        # :reek:TooManyStatements
        def evaluate_assignment(node)
          pattern = node.left
          value = evaluate(node.right)
          binding_sets = unifier.unify(pattern, value, environment)
          return UndefinedValue.new unless binding_sets.size == 1

          apply_bindings(binding_sets.first)
          value
        end

        # :reek:TooManyStatements
        def evaluate_unification(node)
          binding_sets, resolved_value = unification_result(node, environment)
          return UndefinedValue.new unless binding_sets.size == 1

          apply_bindings(binding_sets.first)
          resolved_value
        end

        # :reek:TooManyStatements
        def unification_binding_sets(node, env)
          binding_sets, = unification_result(node, env)
          binding_sets
        end

        # :reek:TooManyStatements
        # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
        def unification_result(node, env)
          left_node = node.left
          right_node = node.right
          right_value = evaluate(right_node)
          right_undefined = right_value.is_a?(UndefinedValue)
          if right_undefined && left_node.is_a?(AST::Reference) && right_node.is_a?(AST::Variable)
            bindings = bind_reference_variable(right_node, reference_bindings_for(left_node, env))
            return [bindings, UndefinedValue.new]
          end
          # @type var binding_sets: Array[Hash[String, Value]]
          binding_sets = []
          binding_sets = unifier.unify(left_node, right_value, env) unless right_undefined
          return [binding_sets, right_value] unless binding_sets.empty?

          left_value = evaluate(left_node)
          return [binding_sets, left_value] if left_value.is_a?(UndefinedValue)

          [unifier.unify(right_node, left_value, env), left_value]
        end
        # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

        # :reek:TooManyStatements
        # :reek:UtilityFunction
        def reference_bindings_for(reference, env)
          base_value = reference_base_override(reference)
          unifier.reference_bindings(
            reference,
            env,
            {},
            base_value: base_value,
            variable_resolver: method(:resolve_reference_variable_key)
          )
        end

        def reference_base_override(reference)
          name = reference_base_name(reference)
          return nil unless name

          resolve_reference_base(name)
        end

        def reference_base_name(reference)
          case reference.base
          in AST::Variable[name:]
            return nil unless unresolved_reference_base?(name)

            name
          else
            nil
          end
        end

        def unresolved_reference_base?(name)
          !environment.local_bound?(name) && environment.lookup(name).is_a?(UndefinedValue)
        end

        def resolve_reference_base(name)
          reference_resolver.resolve_import_variable(name) ||
            reference_resolver.resolve_rule_variable(name)
        end

        # :reek:TooManyStatements
        # :reek:UtilityFunction
        def bind_reference_variable(variable, reference_bindings)
          reference_bindings.filter_map do |(bindings, value)|
            next if value.is_a?(UndefinedValue)

            name = variable.name
            next bindings if name == "_"

            existing = bindings[name]
            next if existing && existing != value

            additions = {} # @type var additions: Hash[String, Value]
            additions[name] = value
            bindings.merge(additions)
          end
        end

        def apply_bindings(bindings)
          bindings.each do |name, binding_value|
            environment.bind(name, binding_value)
          end
          bindings
        end
      end
    end
  end
end
