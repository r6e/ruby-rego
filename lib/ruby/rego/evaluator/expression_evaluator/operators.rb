# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Binary, unary, and logical operators, with their unification binding yields.
      # :reek:DataClump
      class ExpressionEvaluator
        private

        # :reek:TooManyStatements
        def evaluate_binary_op(node)
          operator = node.operator
          return evaluate_assignment(node) if operator == :assign
          return evaluate_unification(node) if operator == :unify
          return evaluate_logical_operator(node) if %i[and or].include?(operator)

          left = evaluate(node.left)
          right = evaluate(node.right)
          OperatorEvaluator.apply(operator, left, right)
        end

        def evaluate_unary_op(node)
          case node
          in AST::UnaryOp[operator:, operand:]
            if operator == :not && operand.is_a?(AST::Every)
              raise EvaluationError.new("Negating every is not supported", rule: nil, location: operand.location)
            end

            OperatorEvaluator.apply_unary(operator, evaluate(operand))
          end
        end

        def handle_unification_operator(node, env, yielder)
          case node.operator
          when :assign
            yield_assignment_bindings(node, env, yielder)
          when :unify
            yield_unification_bindings(node, env, yielder)
          else
            yield_truthy_bindings(node, yielder)
          end
        end

        def evaluate_logical_operator(node)
          case node.operator
          when :and then evaluate_and_operator(node)
          when :or then evaluate_or_operator(node)
          else UndefinedValue.new
          end
        end

        # :reek:TooManyStatements
        def evaluate_and_operator(node)
          left_state = logical_state(evaluate(node.left))
          return FALSE_VALUE if left_state == :falsy

          right_state = logical_state(evaluate(node.right))
          right_truthy = right_state == :truthy
          right_falsy = right_state == :falsy
          return TRUE_VALUE if left_state == :truthy && right_truthy
          return FALSE_VALUE if right_falsy

          UndefinedValue.new
        end

        # :reek:TooManyStatements
        def evaluate_or_operator(node)
          left_state = logical_state(evaluate(node.left))
          return TRUE_VALUE if left_state == :truthy

          right_state = logical_state(evaluate(node.right))
          right_truthy = right_state == :truthy
          right_falsy = right_state == :falsy
          return TRUE_VALUE if right_truthy
          return FALSE_VALUE if left_state == :falsy && right_falsy

          UndefinedValue.new
        end

        # :reek:UtilityFunction
        def logical_state(value)
          return :undefined if value.undefined?

          value.truthy? ? :truthy : :falsy
        end

        def yield_assignment_bindings(node, env, yielder)
          value = evaluate(node.right)
          return if value.is_a?(UndefinedValue)

          binding_sets = unifier.unify(node.left, value, env)
          yielder << binding_sets.first if binding_sets.size == 1
        end

        def yield_unification_bindings(node, env, yielder)
          unification_binding_sets(node, env).each { |bindings| yielder << bindings }
        end

        def yield_truthy_bindings(node, yielder)
          value = evaluate(node)
          empty_bindings = {} # @type var empty_bindings: Hash[String, Value]
          yielder << empty_bindings if logical_state(value) == :truthy
        end

        def yield_reference_bindings(node, env, yielder)
          reference_bindings_for(node, env).each do |(bindings, value)|
            next unless logical_state(value) == :truthy

            yielder << bindings
          end
        end
      end
    end
  end
end
