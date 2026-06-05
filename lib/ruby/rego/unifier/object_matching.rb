# frozen_string_literal: true

module Ruby
  module Rego
    # :reek:DataClump
    # Object-pattern unification: candidate key selection and pair matching.
    class Unifier
      private

      def available_object_keys(object_values, used_keys)
        object_values.keys.reject { |key| used_keys.include?(key) }
      end

      # :reek:LongParameterList
      # rubocop:disable Metrics/MethodLength
      def reduce_object_pairs(pattern_pairs, object_values, env, bindings)
        binding_sets = [ObjectBindingState.new(bindings: bindings, used_keys: Set.new)]
        index = 0
        while index < pattern_pairs.length
          key_pattern, value_pattern = pattern_pairs[index]
          next_sets = [] # @type var next_sets: Array[ObjectBindingState]
          binding_sets.each do |current_state|
            next_sets.concat(unify_object_pair(key_pattern, value_pattern, object_values, env, current_state))
          end
          binding_sets = next_sets
          break if binding_sets.empty?

          index += 1
        end
        binding_sets
      end
      # rubocop:enable Metrics/MethodLength

      # :reek:LongParameterList
      def unify_object_pair(key_pattern, value_pattern, object_values, env, state)
        available_keys = available_object_keys(object_values, state.used_keys)
        candidate_keys = Helpers.candidate_keys_for(key_pattern, available_keys, env, state.bindings)
        return [] if candidate_keys.empty?

        candidate_keys.flat_map do |candidate_key|
          unify_object_candidate(candidate_key, key_pattern, value_pattern, object_values, env, state)
        end
      end

      # :reek:LongParameterList
      # rubocop:disable Metrics/ParameterLists
      def unify_object_candidate(candidate_key, key_pattern, value_pattern, object_values, env, state)
        return [] unless object_values.key?(candidate_key)
        return [] if state.used_keys.include?(candidate_key)

        updated_bindings = Helpers.bind_key_variable(key_pattern, candidate_key, state.bindings, env)
        return [] unless updated_bindings

        unify_with_bindings(value_pattern, object_values[candidate_key], env, updated_bindings).map do |bindings|
          ObjectBindingState.new(bindings: bindings, used_keys: state.used_keys | [candidate_key])
        end
      end
      # rubocop:enable Metrics/ParameterLists
    end
  end
end
