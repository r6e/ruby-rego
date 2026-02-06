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
        def unification_result(node, env)
          left_node = node.left
          right_node = node.right
          right_value = evaluate(right_node)
          binding_sets = [] # @type var binding_sets: Array[Hash[String, Value]]
          binding_sets = unifier.unify(left_node, right_value, env) unless right_value.is_a?(UndefinedValue)
          return [binding_sets, right_value] unless binding_sets.empty?

          left_value = evaluate(left_node)
          return [binding_sets, left_value] if left_value.is_a?(UndefinedValue)

          [unifier.unify(right_node, left_value, env), left_value]
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
