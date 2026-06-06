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
            when 1 then values.each { |value| yield_bindings(yielder, bindings_for(variables[0], value)) }
            when 2 then values.each_with_index do |value, index|
              yield_bindings(yielder, bindings_for_pair(variables, index, value))
            end
            end
          end
        end

        # :reek:NestedIterators
        def each_set_binding(variables, collection_value)
          Enumerator.new do |yielder|
            collection_value.to_ruby.each do |value|
              yield_bindings(yielder, bindings_for(variables[0], value))
            end
          end
        end

        # :reek:NestedIterators
        # :reek:TooManyStatements
        def each_object_binding(variables, collection_value)
          Enumerator.new do |yielder|
            pairs = collection_value.to_ruby
            case variables.length
            when 1 then pairs.each_value { |value| yield_bindings(yielder, bindings_for(variables[0], value)) }
            when 2 then pairs.each { |key, value| yield_bindings(yielder, bindings_for_pair(variables, key, value)) }
            end
          end
        end

        # :reek:UtilityFunction
        def yield_bindings(yielder, binding_sets)
          binding_sets.each { |bindings| yielder << bindings }
        end

        # :reek:NestedIterators
        def bindings_for_pair(variables, first_value, second_value)
          first_sets = bindings_for(variables[0], first_value)
          second_sets = bindings_for(variables[1], second_value)
          first_sets.flat_map { |first| second_sets.filter_map { |second| combine_bindings(first, second) } }
        end

        # @return [Array<Hash{String => Value}>] one binding set for a bare variable
        #   (`[{name => value}]`), or the unification results for a destructuring
        #   pattern (empty when the value does not match the pattern's shape).
        def bindings_for(target, value)
          return [{}] if wildcard?(target)
          return [{ target.name => Value.from_ruby(value) }] if target.is_a?(AST::Variable)

          unifier.unify(target, Value.from_ruby(value), environment)
        end

        # :reek:UtilityFunction
        def wildcard?(target)
          target.is_a?(AST::Variable) && target.name == "_"
        end

        # :reek:UtilityFunction
        def combine_bindings(first, second)
          merged = first.dup
          second.each do |name, value|
            existing = merged[name]
            return nil if existing && existing != value

            merged[name] = value
          end
          merged
        end
      end
    end
  end
end
