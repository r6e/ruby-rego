# frozen_string_literal: true

require "json"
require_relative "../call_name"

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

        def raise_unknown_node(node)
          node_class = node.class
          raise EvaluationError.new("Unsupported AST node: #{node_class}", rule: nil, location: nil)
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

        def every_body_succeeds?(body, bindings)
          environment.with_bindings(bindings) do
            query_evaluator.query_solutions(body, environment).any?
          end
        end

        def every_bindings(variables, collection_value)
          bindings_for_collection(variables, collection_value)
        end

        def bindings_for_collection(variables, collection_value)
          case collection_value
          when ArrayValue then array_bindings_for(variables, collection_value)
          when SetValue then set_bindings_for(variables, collection_value)
          when ObjectValue then object_bindings_for(variables, collection_value)
          end
        end

        def array_bindings_for(variables, collection_value)
          return nil unless [1, 2].include?(variables.length)

          each_array_binding(variables, collection_value)
        end

        def set_bindings_for(variables, collection_value)
          return nil unless variables.length == 1

          each_set_binding(variables, collection_value)
        end

        def object_bindings_for(variables, collection_value)
          return nil unless [1, 2].include?(variables.length)

          each_object_binding(variables, collection_value)
        end

        def with_every_scope(node)
          environment.push_scope
          shadow_every_locals(node)
          yield
        ensure
          environment.pop_scope
        end

        # :reek:TooManyStatements
        def shadow_every_locals(node)
          details = BoundVariableCollector.new.collect_details(node.body)
          explicit = details[:explicit].dup
          explicit.concat(every_variable_names(node))
          explicit.uniq!
          shadow_explicit_locals(explicit)
          shadow_unification_locals(details[:unification], explicit)
        end

        # :reek:UtilityFunction
        def every_variable_names(node)
          [node.key_var, node.value_var].compact.map(&:name)
        end

        def shadow_explicit_locals(names)
          names.each { |name| bind_undefined(name) }
        end

        def shadow_unification_locals(names, explicit_names)
          names.each do |name|
            next if explicit_names.include?(name)
            next unless environment.lookup(name).is_a?(UndefinedValue)

            bind_undefined(name)
          end
        end

        def bind_undefined(name)
          return if Environment::RESERVED_NAMES.include?(name) || name == "_"

          environment.bind(name, UndefinedValue.new)
        end

        def query_evaluator
          return @query_evaluator if @query_evaluator

          raise EvaluationError.new("Query evaluator not configured", rule: nil, location: nil)
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

      # Formats template string values using a stable JSON representation.
      class TemplateValueFormatter
        # @param value [Object]
        def initialize(value)
          @value = value
        end

        # @return [String]
        def render
          case value
          when NilClass then "null"
          when String then value
          when Array, Hash, Set then JSON.generate(canonical_value)
          else value.to_s
          end
        end

        # @return [Object]
        def canonical_value
          case value
          when Hash then canonicalize_hash
          when Array then canonicalize_array
          when Set then canonicalize_set
          else value
          end
        end

        private

        attr_reader :value

        def canonicalize_hash
          result = {} # @type var result: Hash[untyped, untyped]
          value.keys.sort_by(&:to_s).each do |key|
            result[key] = self.class.new(value[key]).canonical_value
          end
          result
        end

        def canonicalize_array
          value.map { |element| self.class.new(element).canonical_value }
        end

        def canonicalize_set
          value
            .to_a
            .map { |element| self.class.new(element).canonical_value }
            .sort_by { |element| JSON.generate(element) }
        end
      end
    end
  end
end
