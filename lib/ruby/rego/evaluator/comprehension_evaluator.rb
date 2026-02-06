# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Evaluates comprehensions in isolated scopes.
      # :reek:TooManyMethods
      # rubocop:disable Metrics/ClassLength
      class ComprehensionEvaluator
        # Tracks object keys for conflict detection.
        class ObjectAccumulator
          def initialize
            @key_sources = {} # @type var @key_sources: Hash[Object, Object]
          end

          # :reek:TooManyStatements
          def add(values, key, value)
            normalized_key = key.is_a?(Symbol) ? key.to_s : key
            if key_sources.key?(normalized_key)
              existing = key_sources[normalized_key]
              raise ObjectKeyConflictError, "Conflicting object keys: #{existing.inspect} and #{key.inspect}"
            end
            key_sources[normalized_key] = key
            values[normalized_key] = value
          end

          private

          attr_reader :key_sources
        end

        private_constant :ObjectAccumulator

        # Bundles object comprehension accumulation state.
        ObjectPairContext = Struct.new(:result_values, :accumulator)
        private_constant :ObjectPairContext

        # @param expression_evaluator [ExpressionEvaluator]
        # @param environment [Environment]
        def initialize(expression_evaluator:, environment:)
          @expression_evaluator = expression_evaluator
          @environment = environment
          @query_evaluator = nil
        end

        # @param query_evaluator [RuleEvaluator]
        # @return [void]
        def attach_query_evaluator(query_evaluator)
          @query_evaluator = query_evaluator
          nil
        end

        # @param node [AST::ArrayComprehension]
        # @return [Value]
        def eval_array(node)
          ArrayValue.new(collect_values(node))
        end

        # @param node [AST::ObjectComprehension]
        # @return [Value]
        def eval_object(node)
          ObjectValue.new(object_pairs(node))
        end

        # @param node [AST::SetComprehension]
        # @return [Value]
        def eval_set(node)
          SetValue.new(collect_values(node))
        end

        private

        attr_reader :expression_evaluator, :environment, :query_evaluator

        def object_pairs(node)
          values = {} # @type var values: Hash[Object, Value]
          context = ObjectPairContext.new(values, ObjectAccumulator.new)
          each_comprehension_binding(node.body) do |bindings|
            apply_object_binding(context, node.term, bindings)
          end
          values
        end

        def apply_object_binding(context, term, bindings)
          environment.with_bindings(bindings) do
            pair = resolve_pair(term)
            return unless pair

            key, value = pair
            context.accumulator.add(context.result_values, key, value)
          end
        end

        def resolve_pair(term)
          key = evaluate_defined_key(term[0])
          return nil if key.is_a?(Value) && key.undefined?

          value = evaluate_defined_value(term[1])
          return nil unless value

          [key, value]
        end

        def each_comprehension_binding(body, &)
          with_comprehension_scope(body) { comprehension_solutions(body).each(&) }
        end

        def collect_values(node)
          values = [] # @type var values: Array[Value]
          each_comprehension_binding(node.body) do |bindings|
            append_value(values, node.term, bindings)
          end
          values
        end

        def append_value(values, term, bindings)
          environment.with_bindings(bindings) do
            value = evaluate_defined_value(term)
            values << value if value
          end
        end

        # :reek:FeatureEnvy
        def evaluate_defined_key(node)
          value = expression_evaluator.evaluate(node)
          return UndefinedValue.new if value.is_a?(Value) && value.undefined?

          value.object_key
        end

        # :reek:FeatureEnvy
        def evaluate_defined_value(node)
          value = expression_evaluator.evaluate(node)
          return nil if value.is_a?(Value) && value.undefined?

          value
        end

        def comprehension_solutions(body)
          return query_evaluator.query_solutions(body, environment) if query_evaluator

          raise EvaluationError.new("Query evaluator not configured", rule: nil, location: nil)
        end

        def with_comprehension_scope(body)
          environment.push_scope
          shadow_comprehension_locals(body)
          yield
        ensure
          environment.pop_scope
        end

        def shadow_comprehension_locals(body)
          details = BoundVariableCollector.new.collect_details(body)
          explicit = details[:explicit]
          shadow_explicit_locals(explicit)
          shadow_unification_locals(details[:unification], explicit)
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
      end
      # rubocop:enable Metrics/ClassLength
    end
  end
end
