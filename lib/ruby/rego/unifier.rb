# frozen_string_literal: true

require_relative "ast"
require_relative "environment"
require_relative "value"

module Ruby
  module Rego
    # Handles pattern matching and unification for Rego terms.
    # :reek:DataClump
    # rubocop:disable Metrics/ClassLength
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

      # Bundles inputs for reference key candidate evaluation.
      ReferenceKeyContext = Struct.new(:current, :env, :bindings, :variable_resolver, keyword_init: true)
      # Tracks bindings and object keys already matched in a pattern.
      ObjectBindingState = Struct.new(:bindings, :used_keys, keyword_init: true)

      def initialize(variable_resolver: nil)
        @variable_resolver = variable_resolver
      end

      # @param pattern [Object]
      # @param value [Object]
      # @param env [Environment]
      # @return [Array<Hash{String => Value}>]
      def unify(pattern, value, env)
        bindings = {} # @type var bindings: Hash[String, Value]
        unify_with_bindings(pattern, value, env, bindings)
      end

      # Resolve reference bindings for references with variable keys.
      #
      # @param reference [AST::Reference]
      # @param env [Environment]
      # @param bindings [Hash{String => Value}]
      # @param variable_resolver [#call, nil]
      # @return [Array<Array(Hash{String => Value}, Value)>]
      # :reek:LongParameterList
      def reference_bindings(reference, env, bindings = {}, base_value: nil, variable_resolver: nil)
        base_value ||= resolve_reference_base(reference.base, env, bindings)
        return [] if base_value.is_a?(UndefinedValue)

        resolver = variable_resolver || @variable_resolver
        traverse_reference(base_value, reference.path, env, bindings, variable_resolver: resolver)
      end

      # @param pattern_elems [Array<Object>, AST::ArrayLiteral]
      # @param value_array [Object]
      # @param env [Environment]
      # @param bindings [Hash{String => Value}]
      # @return [Array<Hash{String => Value}>]
      # :reek:LongParameterList
      def unify_array(pattern_elems, value_array, env, bindings = {})
        pattern_elements = pattern_elems.is_a?(AST::ArrayLiteral) ? pattern_elems.elements : pattern_elems
        elements = Helpers.normalize_array(value_array)
        return [] unless elements && elements.length == pattern_elements.length

        reduce_array_bindings(pattern_elements, elements, env, bindings)
      end

      # @param pattern_pairs [Array<Array(Object, Object)>, AST::ObjectLiteral]
      # @param value_obj [Object]
      # @param env [Environment]
      # @param bindings [Hash{String => Value}]
      # @return [Array<Hash{String => Value}>]
      # :reek:LongParameterList
      def unify_object(pattern_pairs, value_obj, env, bindings = {})
        pairs = pattern_pairs.is_a?(AST::ObjectLiteral) ? pattern_pairs.pairs : pattern_pairs
        object_values = Helpers.normalize_object(value_obj)
        return [] unless object_values
        return [] unless pairs.length == object_values.length

        reduce_object_pairs(pairs, object_values, env, bindings).map(&:bindings)
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
        return unify_reference(pattern, resolved_value, env, bindings) if pattern.is_a?(AST::Reference)
        return unify_array(pattern, resolved_value, env, bindings) if pattern.is_a?(AST::ArrayLiteral)
        return unify_object(pattern, resolved_value, env, bindings) if pattern.is_a?(AST::ObjectLiteral)

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

      def available_object_keys(object_values, used_keys)
        object_values.keys.reject { |key| used_keys.include?(key) }
      end

      # :reek:TooManyStatements
      # :reek:LongParameterList
      # :reek:FeatureEnvy
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
      # :reek:FeatureEnvy
      def unify_object_pair(key_pattern, value_pattern, object_values, env, state)
        available_keys = available_object_keys(object_values, state.used_keys)
        candidate_keys = Helpers.candidate_keys_for(key_pattern, available_keys, env, state.bindings)
        return [] if candidate_keys.empty?

        candidate_keys.flat_map do |candidate_key|
          unify_object_candidate(candidate_key, key_pattern, value_pattern, object_values, env, state)
        end
      end

      # :reek:LongParameterList
      # :reek:FeatureEnvy
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

      # :reek:LongParameterList
      def unify_reference(pattern, resolved_value, env, bindings)
        # @type var results: Array[Hash[String, Value]]
        results = []
        reference_bindings(pattern, env, bindings).each_with_object(results) do |(candidate_bindings, value), acc|
          next if value.is_a?(UndefinedValue)
          next unless value == resolved_value

          acc << candidate_bindings
        end
      end

      def resolve_reference_base(base, env, bindings)
        return env.input if base.is_a?(AST::Variable) && base.name == "input"
        return env.data if base.is_a?(AST::Variable) && base.name == "data"

        if base.is_a?(AST::Variable)
          bound = Helpers.bound_value_for(base.name, bindings, env)
          return bound if bound
        end

        Helpers.scalar_pattern_value(base, env)
      end

      # :reek:LongParameterList
      # rubocop:disable Metrics/CyclomaticComplexity, Metrics/MethodLength
      def traverse_reference(current, path, env, bindings, variable_resolver: nil)
        return [[bindings, current]] if path.empty?
        return [] unless current.is_a?(ObjectValue) || current.is_a?(ArrayValue)

        segment = path.first
        key_node = segment.is_a?(AST::RefArg) ? segment.value : segment
        candidates = reference_key_candidates(current, key_node, env, bindings, variable_resolver: variable_resolver)
        candidates.flat_map do |candidate_key, candidate_bindings|
          next [] if candidate_bindings.nil?

          next_value = current.fetch_reference(candidate_key)
          next [] if next_value.is_a?(UndefinedValue)

          traverse_reference(next_value, path.drop(1), env, candidate_bindings, variable_resolver: variable_resolver)
        end
      end
      # rubocop:enable Metrics/CyclomaticComplexity, Metrics/MethodLength

      # :reek:LongParameterList
      def reference_key_candidates(current, key_node, env, bindings, variable_resolver: nil)
        keys = reference_keys_for(current)
        return [] if keys.empty?

        context = ReferenceKeyContext.new(
          current: current,
          env: env,
          bindings: bindings,
          variable_resolver: variable_resolver
        )
        return variable_key_candidates(key_node, keys, context) if key_node.is_a?(AST::Variable)

        value_key_candidates(key_node, context)
      end

      def variable_key_candidates(key_node, keys, context)
        name = key_node.name
        return wildcard_key_candidates(keys, context.bindings) if name == "_"

        bound_candidate = bound_key_candidate(name, context)
        return bound_candidate if bound_candidate

        resolved_candidate = resolved_key_candidate(name, context)
        return resolved_candidate if resolved_candidate

        binding_key_candidates(name, keys, context.bindings)
      end

      def wildcard_key_candidates(keys, bindings)
        keys.map { |key| [key, bindings] }
      end

      def bound_key_candidate(name, context)
        bound = Helpers.bound_value_for(name, context.bindings, context.env)
        return nil unless bound

        [[normalize_reference_key(context.current, bound.to_ruby), context.bindings]]
      end

      def resolved_key_candidate(name, context)
        resolved = resolve_variable_reference(name, context.variable_resolver)
        return nil unless resolved

        normalized = normalize_reference_key(context.current, resolved_reference_value(resolved))
        [[normalized, context.bindings]]
      end

      def binding_key_candidates(name, keys, bindings)
        keys.map do |key|
          new_bindings = Helpers.merge_bindings(bindings, name => Value.from_ruby(key))
          [key, new_bindings]
        end
      end

      def value_key_candidates(key_node, context)
        key_value = Helpers.value_for_pattern(key_node, context.env)
        return [] if key_value.is_a?(UndefinedValue)

        [[normalize_reference_key(context.current, key_value.to_ruby), context.bindings]]
      end

      def resolved_reference_value(resolved)
        resolved.is_a?(Value) ? resolved.to_ruby : resolved
      end

      def resolve_variable_reference(name, resolver)
        return nil unless resolver

        resolved = resolver.call(name)
        return nil if resolved.nil? || resolved.is_a?(UndefinedValue)

        resolved
      end

      def reference_keys_for(current)
        case current
        when ObjectValue
          current.value.keys
        when ArrayValue
          (0...current.value.length).to_a
        else
          []
        end
      end

      def normalize_reference_key(current, key)
        return Helpers.normalize_key(key) if current.is_a?(ObjectValue)

        key
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
end
