# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Binding helpers for rule evaluation.
      # :reek:DataClump
      class RuleEvaluator
        private

        # :reek:TooManyStatements
        # :reek:NestedIterators
        def each_some_solution(literal)
          Enumerator.new do |yielder|
            collection = literal.collection
            unless collection
              yielder << {}
              next
            end

            collection_value = expression_evaluator.evaluate(collection)
            next if collection_value.undefined?

            collection_bindings(literal.variables, collection_value).each { |bindings| yielder << bindings }
          end
        end

        def collection_bindings(variables, collection_value)
          case collection_value
          when ArrayValue
            each_array_binding(variables, collection_value)
          when SetValue
            each_set_binding(variables, collection_value)
          when ObjectValue
            each_object_binding(variables, collection_value)
          else
            empty_bindings_enum
          end
        end

        # :reek:DataClump
        # :reek:NestedIterators
        # :reek:TooManyStatements
        def each_array_binding(variables, collection_value)
          Enumerator.new do |yielder|
            values = collection_value.to_ruby
            case variables.length
            when 1 then values.each { |value| yielder << bindings_for(variables[0], value) }
            when 2 then values.each_with_index { |value, index| yielder << bindings_for_pair(variables, index, value) }
            end
          end
        end

        # :reek:DataClump
        # :reek:NestedIterators
        def each_set_binding(variables, collection_value)
          return empty_bindings_enum unless variables.length == 1

          Enumerator.new do |yielder|
            collection_value.to_ruby.each do |value|
              yielder << bindings_for(variables[0], value)
            end
          end
        end

        # :reek:DataClump
        # :reek:NestedIterators
        # :reek:TooManyStatements
        def each_object_binding(variables, collection_value)
          Enumerator.new do |yielder|
            pairs = collection_value.to_ruby
            case variables.length
            when 1 then pairs.each_key { |key| yielder << bindings_for(variables[0], key) }
            when 2 then pairs.each { |key, value| yielder << bindings_for_pair(variables, key, value) }
            end
          end
        end

        def bindings_for_pair(variables, first_value, second_value)
          bindings = bindings_for(variables[0], first_value)
          bindings.merge!(bindings_for(variables[1], second_value))
          bindings
        end

        # :reek:UtilityFunction
        def bindings_for(variable, value)
          name = variable.name
          return {} if name == "_"

          { name => Value.from_ruby(value) }
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
