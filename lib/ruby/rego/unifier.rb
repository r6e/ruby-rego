# frozen_string_literal: true

require_relative "ast"
require_relative "environment"
require_relative "value"

module Ruby
  module Rego
    # Handles pattern matching and unification for Rego terms.
    # :reek:DataClump
    class Unifier
      # Internal helpers that do not rely on instance state.
      module Helpers
        def self.scalar_pattern_value(pattern, env)
          return Value.from_ruby(pattern.value) if pattern.is_a?(AST::Literal)
          return env.resolve_reference(pattern) if pattern.is_a?(AST::Reference)
          return pattern if pattern.is_a?(Value)

          Value.from_ruby(pattern)
        rescue ArgumentError, ObjectKeyConflictError
          UndefinedValue.new
        end

        def self.normalize_value(value, env)
          return value if value.is_a?(Value)
          return env.resolve_reference(value) if value.is_a?(AST::Reference)
          return Value.from_ruby(value.value) if value.is_a?(AST::Literal)

          Value.from_ruby(value)
        rescue ArgumentError, ObjectKeyConflictError
          UndefinedValue.new
        end

        def self.value_for_pattern(pattern, env)
          Helpers.scalar_pattern_value(pattern, env)
        end

        def self.normalize_array(value)
          return normalize_elements(value.to_ruby) if value.is_a?(ArrayValue)
          return normalize_elements(value) if value.is_a?(Array)

          nil
        end

        def self.normalize_elements(elements)
          values = [] # @type var values: Array[Value]
          elements.each do |element|
            values << Value.from_ruby(element)
          rescue ArgumentError, ObjectKeyConflictError
            return nil
          end
          values
        end

        def self.normalize_key(key)
          key.is_a?(Symbol) ? key.to_s : key
        end

        def self.object_pairs(value)
          return value.to_ruby if value.is_a?(ObjectValue)
          return value if value.is_a?(Hash)

          nil
        end

        # :reek:TooManyStatements
        def self.normalize_object(value)
          return nil unless (pairs = object_pairs(value))

          values = {} # @type var values: Hash[Object, Value]
          pairs.each do |key, val|
            normalized_key = normalize_key(key)
            return nil if values.key?(normalized_key)

            values[normalized_key] = Value.from_ruby(val)
          end
          values
        rescue ArgumentError, ObjectKeyConflictError
          nil
        end

        def self.bound_value_for(name, bindings, env)
          bound = bindings[name]
          return bound if bound && !bound.is_a?(UndefinedValue)

          env_value = env.lookup(name)
          return nil if env_value.is_a?(UndefinedValue)

          env_value
        end

        def self.merge_bindings(bindings, additions)
          conflict = additions.any? do |name, value|
            existing = bindings[name]
            existing && existing != value
          end
          return nil if conflict

          bindings.merge(additions)
        end

        # :reek:LongParameterList
        # :reek:TooManyStatements
        def self.unify_variable(variable, value, env, bindings)
          name = variable.name
          return [bindings] if name == "_"

          bound_value = bound_value_for(name, bindings, env)
          return bound_value == value ? [bindings] : [] if bound_value

          [bindings.merge(name => value)]
        end

        # :reek:TooManyStatements
        # :reek:LongParameterList
        def self.candidate_keys_for(key_pattern, keys, env, bindings)
          if key_pattern.is_a?(AST::Variable)
            name = key_pattern.name
            return keys if name == "_"

            bound_value = bound_value_for(name, bindings, env)
            return [normalize_key(bound_value.to_ruby)] if bound_value

            return keys
          end

          key_value = value_for_pattern(key_pattern, env)
          return [] if key_value.is_a?(UndefinedValue)

          [normalize_key(key_value.to_ruby)]
        end

        # :reek:LongParameterList
        # :reek:ControlParameter
        def self.match_scalar(pattern, resolved_value, env, bindings)
          pattern_value = scalar_pattern_value(pattern, env)
          pattern_value == resolved_value ? [bindings] : []
        end

        # :reek:LongParameterList
        # :reek:TooManyStatements
        def self.bind_key_variable(key_pattern, candidate_key, bindings, env)
          return bindings unless key_pattern.is_a?(AST::Variable)

          name = key_pattern.name
          return bindings if name == "_"

          bound_value = bound_value_for(name, bindings, env)
          return bindings if bound_value

          merge_bindings(bindings, name => Value.from_ruby(candidate_key))
        end
      end

      # @param pattern [Object]
      # @param value [Object]
      # @param env [Environment]
      # @return [Array<Hash{String => Value}>]
      def unify(pattern, value, env)
        bindings = {} # @type var bindings: Hash[String, Value]
        unify_with_bindings(pattern, value, env, bindings)
      end

      # @param pattern_elems [Array<Object>]
      # @param value_array [Object]
      # @param env [Environment]
      # @param bindings [Hash{String => Value}]
      # @return [Array<Hash{String => Value}>]
      # :reek:LongParameterList
      def unify_array(pattern_elems, value_array, env, bindings = {})
        elements = Helpers.normalize_array(value_array)
        return [] unless elements && elements.length == pattern_elems.length

        reduce_array_bindings(pattern_elems, elements, env, bindings)
      end

      # @param pattern_pairs [Array<Array(Object, Object)>]
      # @param value_obj [Object]
      # @param env [Environment]
      # @param bindings [Hash{String => Value}]
      # @return [Array<Hash{String => Value}>]
      # :reek:LongParameterList
      def unify_object(pattern_pairs, value_obj, env, bindings = {})
        object_values = Helpers.normalize_object(value_obj)
        return [] unless object_values

        reduce_object_pairs(pattern_pairs, object_values, env, bindings)
      end

      private

      # :reek:LongParameterList
      def unify_with_bindings(pattern, value, env, bindings)
        resolved_value = Helpers.normalize_value(value, env)
        return [] if resolved_value.is_a?(UndefinedValue)

        apply_unification(pattern, resolved_value, env, bindings)
      rescue ArgumentError
        []
      end

      # :reek:LongParameterList
      # :reek:FeatureEnvy
      def structured_unification(pattern, resolved_value, env, bindings)
        return Helpers.unify_variable(pattern, resolved_value, env, bindings) if pattern.is_a?(AST::Variable)
        return unify_array(pattern.elements, resolved_value, env, bindings) if pattern.is_a?(AST::ArrayLiteral)
        return unify_object(pattern.pairs, resolved_value, env, bindings) if pattern.is_a?(AST::ObjectLiteral)

        nil
      end

      # :reek:LongParameterList
      def apply_unification(pattern, resolved_value, env, bindings)
        structured = structured_unification(pattern, resolved_value, env, bindings)
        return structured if structured

        Helpers.match_scalar(pattern, resolved_value, env, bindings)
      end

      # :reek:TooManyStatements
      # :reek:LongParameterList
      # :reek:FeatureEnvy
      # rubocop:disable Metrics/MethodLength
      def reduce_array_bindings(pattern_elems, elements, env, bindings)
        binding_sets = [bindings]
        index = 0
        while index < pattern_elems.length
          element = pattern_elems[index]
          next_sets = [] # @type var next_sets: Array[Hash[String, Value]]
          binding_sets.each do |current|
            next_sets.concat(unify_with_bindings(element, elements[index], env, current))
          end
          binding_sets = next_sets
          break if binding_sets.empty?

          index += 1
        end
        binding_sets
      end
      # rubocop:enable Metrics/MethodLength

      # :reek:TooManyStatements
      # :reek:LongParameterList
      # :reek:FeatureEnvy
      # rubocop:disable Metrics/MethodLength
      def reduce_object_pairs(pattern_pairs, object_values, env, bindings)
        binding_sets = [bindings]
        index = 0
        while index < pattern_pairs.length
          key_pattern, value_pattern = pattern_pairs[index]
          next_sets = [] # @type var next_sets: Array[Hash[String, Value]]
          binding_sets.each do |current|
            next_sets.concat(unify_object_pair(key_pattern, value_pattern, object_values, env, current))
          end
          binding_sets = next_sets
          break if binding_sets.empty?

          index += 1
        end
        binding_sets
      end
      # rubocop:enable Metrics/MethodLength

      # :reek:LongParameterList
      # :reek:FeatureEnvy
      def unify_object_pair(key_pattern, value_pattern, object_values, env, bindings)
        candidate_keys = Helpers.candidate_keys_for(key_pattern, object_values.keys, env, bindings)
        return [] if candidate_keys.empty?

        candidate_keys.flat_map do |candidate_key|
          unify_object_candidate(candidate_key, key_pattern, value_pattern, object_values, env, bindings)
        end
      end

      # :reek:LongParameterList
      # :reek:FeatureEnvy
      # rubocop:disable Metrics/ParameterLists
      def unify_object_candidate(candidate_key, key_pattern, value_pattern, object_values, env, bindings)
        return [] unless object_values.key?(candidate_key)

        updated_bindings = Helpers.bind_key_variable(key_pattern, candidate_key, bindings, env)
        return [] unless updated_bindings

        unify_with_bindings(value_pattern, object_values[candidate_key], env, updated_bindings)
      end
      # rubocop:enable Metrics/ParameterLists
    end
  end
end
