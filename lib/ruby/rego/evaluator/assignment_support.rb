# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Shared helpers for assignment/unification logic.
      module AssignmentSupport
        private

        def evaluate_assignment(node)
          left = assignment_operand(node.left)
          right = assignment_operand(node.right)

          assignment_value(left, right)
        end

        def assignment_operand(node)
          { node: node, value: evaluate(node) }
        end

        def assignment_value(left, right)
          left_node, left_value = left.values_at(:node, :value)
          right_node, right_value = right.values_at(:node, :value)

          bind_unassigned_variable(left_node, left_value, right_value) ||
            bind_unassigned_variable(right_node, right_value, left_value) ||
            (left_value == right_value ? left_value : UndefinedValue.new)
        end

        def bind_unassigned_variable(node, node_value, other_value)
          return nil unless node_value.is_a?(UndefinedValue)

          case node
          in AST::Variable[name:]
            environment.bind(name, other_value)
            other_value
          else
            nil
          end
        end
      end
    end
  end
end
