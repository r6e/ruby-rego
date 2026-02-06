# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Evaluates expressions to Rego values.
      # :reek:TooManyInstanceVariables
      # :reek:DataClump
      # :reek:TooManyMethods
      # rubocop:disable Metrics/ClassLength
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
          [AST::ArrayComprehension, ->(node, evaluator) { evaluator.send(:eval_array_comprehension, node) }],
          [AST::ObjectComprehension, ->(node, evaluator) { evaluator.send(:eval_object_comprehension, node) }],
          [AST::SetComprehension, ->(node, evaluator) { evaluator.send(:eval_set_comprehension, node) }],
          [AST::Call, ->(_call, _evaluator) { UndefinedValue.new }]
        ].freeze

        include AssignmentSupport

        # @param environment [Environment]
        # @param reference_resolver [ReferenceResolver]
        # @param unifier [Unifier]
        # :reek:TooManyStatements
        def initialize(environment:, reference_resolver:, unifier: Unifier.new)
          @environment = environment
          @reference_resolver = reference_resolver
          @dispatch = build_dispatch
          @unifier = unifier
          @object_literal_evaluator = ObjectLiteralEvaluator.new(expression_evaluator: self)
          @comprehension_evaluator = ComprehensionEvaluator.new(
            expression_evaluator: self,
            environment: environment
          )
        end

        # @param query_evaluator [RuleEvaluator]
        # @return [void]
        def attach_query_evaluator(query_evaluator)
          comprehension_evaluator.attach_query_evaluator(query_evaluator)
          nil
        end

        # @param node [Object]
        # @return [Value]
        def evaluate(node)
          return node if node.is_a?(Value)

          dispatch.primitive_value(node) || dispatch.dispatch_node(node, self) || raise_unknown_node(node)
        end

        # @param node [Object]
        # @param env [Environment]
        # @return [Enumerator]
        def eval_with_unification(node, env = environment)
          Enumerator.new do |yielder|
            if node.is_a?(AST::BinaryOp)
              handle_unification_operator(node, env, yielder)
              next
            end

            yield_truthy_bindings(node, yielder)
          end
        end

        private

        attr_reader :environment, :reference_resolver, :object_literal_evaluator,
                    :dispatch, :unifier, :comprehension_evaluator

        # :reek:UtilityFunction
        def build_dispatch
          ExpressionDispatch.new(
            primitive_types: PRIMITIVE_TYPES,
            node_evaluators: NODE_EVALUATORS
          )
        end

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

        def eval_array_comprehension(node)
          comprehension_evaluator.eval_array(node)
        end

        def eval_object_comprehension(node)
          comprehension_evaluator.eval_object(node)
        end

        def eval_set_comprehension(node)
          comprehension_evaluator.eval_set(node)
        end

        # :reek:TooManyStatements
        def evaluate_binary_op(node)
          operator = node.operator
          return evaluate_assignment(node) if operator == :assign
          return evaluate_unification(node) if operator == :unify

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

        def yield_assignment_bindings(node, env, yielder)
          value = evaluate(node.right)
          binding_sets = unifier.unify(node.left, value, env)
          yielder << binding_sets.first if binding_sets.size == 1
        end

        def yield_unification_bindings(node, env, yielder)
          unification_binding_sets(node, env).each { |bindings| yielder << bindings }
        end

        def yield_truthy_bindings(node, yielder)
          value = evaluate(node)
          empty_bindings = {} # @type var empty_bindings: Hash[String, Value]
          yielder << empty_bindings if value.truthy?
        end
      end
      # rubocop:enable Metrics/ClassLength
    end
  end
end
