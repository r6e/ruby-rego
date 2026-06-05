# frozen_string_literal: true

require_relative "ast"
require_relative "environment"
require_relative "value"

module Ruby
  module Rego
    # Handles pattern matching and unification for Rego terms.
    # :reek:DataClump
    class Unifier
      # Bundles inputs for reference key candidate evaluation.
      ReferenceKeyContext = Struct.new(:current, :env, :bindings, :variable_resolver)
      # Tracks bindings and object keys already matched in a pattern.
      ObjectBindingState = Struct.new(:bindings, :used_keys)

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

      # :reek:LongParameterList
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
    end
  end
end

require_relative "unifier/helpers"
require_relative "unifier/object_matching"
require_relative "unifier/reference_resolution"
require_relative "unifier/key_candidates"
