# frozen_string_literal: true

require "json"
require_relative "../call_name"
require_relative "template_value_formatter"

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
          [AST::Every, ->(node, evaluator) { evaluator.send(:evaluate_every, node) }],
          [AST::Call, ->(call, evaluator) { evaluator.send(:evaluate_call, call) }],
          [AST::TemplateString, ->(node, evaluator) { evaluator.send(:evaluate_template_string, node) }]
        ].freeze
        TRUE_VALUE = BooleanValue.new(true)
        FALSE_VALUE = BooleanValue.new(false)

        include AssignmentSupport
        include BindingHelpers
        include LocalShadowing

        # @param environment [Environment]
        # @param reference_resolver [ReferenceResolver]
        # :reek:TooManyStatements
        def initialize(environment:, reference_resolver:)
          @environment = environment
          @reference_resolver = reference_resolver
          @dispatch = build_dispatch
          @unifier = Unifier.new(variable_resolver: method(:resolve_reference_variable_key))
          @object_literal_evaluator = ObjectLiteralEvaluator.new(expression_evaluator: self)
          @comprehension_evaluator = ComprehensionEvaluator.new(
            expression_evaluator: self,
            environment: environment
          )
          @query_evaluator = nil
        end

        # @param query_evaluator [RuleEvaluator]
        # @return [void]
        def attach_query_evaluator(query_evaluator)
          @query_evaluator = query_evaluator
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
            case node
            when AST::BinaryOp
              handle_unification_operator(node, env, yielder)
            when AST::Reference
              yield_reference_bindings(node, env, yielder)
            else
              yield_truthy_bindings(node, yielder)
            end
          end
        end

        # :reek:UtilityFunction
        def self.call_name(node)
          CallName.call_name(node)
        end

        def self.reference_call_name(reference)
          CallName.reference_call_name(reference)
        end
        private_class_method :reference_call_name

        def self.reference_base_name(reference)
          CallName.reference_base_name(reference)
        end
        private_class_method :reference_base_name

        def self.reference_call_segments(path)
          CallName.reference_call_segments(path)
        end
        private_class_method :reference_call_segments

        def self.dot_ref_segment_value(segment)
          CallName.dot_ref_segment_value(segment)
        end
        private_class_method :dot_ref_segment_value

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
        def evaluate_every(node)
          collection_value = environment.with_bindings({}) { evaluate(node.domain) }
          return UndefinedValue.new if collection_value.is_a?(UndefinedValue)

          variables = [node.key_var, node.value_var].compact
          bindings_enum = every_bindings(variables, collection_value)
          return UndefinedValue.new unless bindings_enum

          evaluate_every_bindings(node, bindings_enum)
        end

        def evaluate_every_bindings(node, bindings_enum)
          with_every_scope(node) do
            bindings_enum.each do |bindings|
              return UndefinedValue.new unless every_body_succeeds?(node.body, bindings)
            end
            BooleanValue.new(true)
          end
        end

        def query_evaluator
          return @query_evaluator if @query_evaluator

          raise EvaluationError.new("Query evaluator not configured", rule: nil, location: nil)
        end

        # :reek:TooManyStatements
        # :reek:UtilityFunction
        # :reek:FeatureEnvy
        def format_template_value(value)
          return "<undefined>" if logical_state(value) == :undefined

          ruby = value.is_a?(Value) ? value.to_ruby : value
          TemplateValueFormatter.new(ruby).render
        end
      end
      # rubocop:enable Metrics/ClassLength
    end
  end
end

require_relative "expression_evaluator/node_evaluation"
require_relative "expression_evaluator/operators"
require_relative "expression_evaluator/quantifiers"
