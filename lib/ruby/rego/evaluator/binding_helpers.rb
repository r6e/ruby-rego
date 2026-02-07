# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Shared helpers for collection binding iteration.
      # :reek:DataClump
      module BindingHelpers
        private

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

        # :reek:NestedIterators
        def each_set_binding(variables, collection_value)
          Enumerator.new do |yielder|
            collection_value.to_ruby.each do |value|
              yielder << bindings_for(variables[0], value)
            end
          end
        end

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
      end
    end
  end
end
