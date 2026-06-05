# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # The every quantifier: body success and collection-binding evaluation.
      # :reek:DataClump
      class ExpressionEvaluator
        private

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
      end
    end
  end
end
