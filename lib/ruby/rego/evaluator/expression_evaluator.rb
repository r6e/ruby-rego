# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Evaluates expressions to Rego values.
      class ExpressionEvaluator
        PRIMITIVE_TYPES = [String, Numeric, TrueClass, FalseClass, Array, Hash, Set, NilClass].freeze
        NODE_EVALUATORS = [
          [AST::Literal, ->(literal, _evaluator) { Value.from_ruby(literal.value) }],
          [AST::Variable, ->(variable, evaluator) { evaluator.send(:evaluate_variable, variable) }],
          [AST::Reference, ->(reference, evaluator) { evaluator.send(:evaluate_reference, reference) }],
          [AST::BinaryOp, ->(binary_op, evaluator) { evaluator.send(:evaluate_binary_op, binary_op) }],
          [AST::UnaryOp, ->(unary_op, evaluator) { evaluator.send(:evaluate_unary_op, unary_op) }],
          [AST::ArrayLiteral, ->(node, evaluator) { evaluator.send(:evaluate_array_literal, node) }],
          [AST::ObjectLiteral, ->(node, evaluator) { evaluator.send(:evaluate_object_literal, node) }],
          [AST::SetLiteral, ->(node, evaluator) { evaluator.send(:evaluate_set_literal, node) }],
          [AST::Call, ->(_call, _evaluator) { UndefinedValue.new }]
        ].freeze

        include AssignmentSupport

        # @param environment [Environment]
        # @param reference_resolver [ReferenceResolver]
        def initialize(environment:, reference_resolver:)
          @environment = environment
          @reference_resolver = reference_resolver
          @dispatch = ExpressionDispatch.new(
            primitive_types: PRIMITIVE_TYPES,
            node_evaluators: NODE_EVALUATORS
          )
          @object_literal_evaluator = ObjectLiteralEvaluator.new(expression_evaluator: self)
        end

        # @param node [Object]
        # @return [Value]
        def evaluate(node)
          return node if node.is_a?(Value)

          dispatch.primitive_value(node) || dispatch.dispatch_node(node, self) || raise_unknown_node(node)
        end

        private

        attr_reader :environment, :reference_resolver, :object_literal_evaluator, :dispatch

        def evaluate_variable(node)
          name = node.name
          return UndefinedValue.new if name == "_"

          environment.lookup(name)
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

        def evaluate_binary_op(node)
          operator = node.operator
          return evaluate_assignment(node) if %i[assign unify].include?(operator)

          left = evaluate(node.left)
          right = evaluate(node.right)
          OperatorEvaluator.apply(operator, left, right)
        end

        def raise_unknown_node(node)
          node_class = node.class
          raise EvaluationError.new("Unsupported AST node: #{node_class}", rule: nil, location: nil)
        end

        def evaluate_unary_op(node)
          case node
          in AST::UnaryOp[operator:, operand:]
            OperatorEvaluator.apply_unary(operator, evaluate(operand))
          end
        end
      end
    end
  end
end
