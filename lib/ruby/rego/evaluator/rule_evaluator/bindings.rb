# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Binding helpers for rule evaluation.
      # :reek:DataClump
      class RuleEvaluator
        include BindingHelpers

        private

        # :reek:TooManyStatements
        # :reek:NestedIterators
        def eval_some_decl(literal, _env = environment)
          Enumerator.new do |yielder|
            collection = literal.collection
            next yield_empty_bindings(yielder) unless collection

            collection_value = expression_evaluator.evaluate(collection)
            next if collection_value.undefined?

            collection_bindings(literal.variables, collection_value).each { |bindings| yielder << bindings }
          end
        end

        # :reek:UtilityFunction
        def yield_empty_bindings(yielder)
          empty_bindings = {} # @type var empty_bindings: Hash[String, Value]
          yielder << empty_bindings
        end

        def each_some_solution(literal)
          eval_some_decl(literal, environment)
        end

        def collection_bindings(variables, collection_value)
          case collection_value
          when ArrayValue
            each_array_binding(variables, collection_value)
          when SetValue
            variables.length == 1 ? each_set_binding(variables, collection_value) : empty_bindings_enum
          when ObjectValue
            each_object_binding(variables, collection_value)
          else
            empty_bindings_enum
          end
        end

        # :reek:UtilityFunction
        # :reek:TooManyStatements
        def merge_bindings(existing, additions)
          merged = existing.dup
          additions.each do |name, value|
            current = merged[name]
            return nil if current && current != value

            merged[name] = value
          end
          merged
        end

        # :reek:UtilityFunction
        def empty_bindings_enum
          Enumerator.new { |yielder| yielder }
        end
      end
    end
  end
end
