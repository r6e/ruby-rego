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
            when 2
              values.each_with_index do |value, index|
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

        def yield_bindings(yielder, binding_sets)
          binding_sets.each { |bindings| yielder << bindings }
        end

        def bindings_for_pair(variables, first_value, second_value)
          first_sets = bindings_for(variables[0], first_value)
          second_sets = bindings_for(variables[1], second_value)
          first_sets.product(second_sets).filter_map { |first, second| merge_bindings(first, second) }
        end

        # @return [Array<Hash{String => Value}>] one binding set for a bare variable
        #   (`[{name => value}]`), or the unification results for a destructuring
        #   pattern (empty when the value does not match the pattern's shape).
        def bindings_for(target, value)
          return [{}] if wildcard?(target)
          return [{ target.name => Value.from_ruby(value) }] if target.is_a?(AST::Variable)

          unifier.unify(target, Value.from_ruby(value), environment)
        end

        def wildcard?(target)
          target.is_a?(AST::Variable) && target.name == "_"
        end

        # Merge two binding sets; nil when a shared name has conflicting values
        # (a unification constraint).
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
      end
    end
  end
end
