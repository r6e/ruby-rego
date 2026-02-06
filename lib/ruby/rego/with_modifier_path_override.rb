# frozen_string_literal: true

require_relative "errors"

module Ruby
  module Rego
    # Applies a path-based override to a Ruby object.
    # :reek:DataClump
    # :reek:FeatureEnvy
    # :reek:TooManyStatements
    # :reek:DuplicateMethodCall
    class WithModifierPathOverride
      # @param base_value [Object]
      # @param keys [Array<Object>]
      # @param replacement [Object]
      # @param location [Location, nil]
      def initialize(base_value:, keys:, replacement:, location: nil)
        @base_value = base_value
        @keys = keys
        @replacement = replacement
        @location = location
      end

      # @return [Object]
      def apply
        apply_to(base_value, keys)
      end

      private

      attr_reader :base_value, :keys, :replacement, :location

      def apply_to(container, path_keys)
        return replacement if path_keys.empty?

        return apply_hash(container, path_keys) if container.is_a?(Hash)
        return apply_array(container, path_keys) if container.is_a?(Array)

        apply_missing_container(path_keys)
      end

      def apply_hash(container, path_keys)
        key = path_keys.first
        rest = path_keys.drop(1)
        updated = container.dup
        normalized_key = key.is_a?(Symbol) ? key.to_s : key
        updated[normalized_key] = apply_to(container[normalized_key], rest)
        updated
      end

      def apply_array(container, path_keys)
        key = path_keys.first
        rest = path_keys.drop(1)
        index = array_index(key)
        updated = container.dup
        updated[index] = apply_to(container[index], rest)
        updated
      end

      def array_index(key)
        return key if key.is_a?(Integer)
        return Integer(key, 10) if numeric_key?(key)

        error = invalid_index_error(key)
        raise error
      rescue ArgumentError
        error = invalid_index_error(key)
        raise error
      end

      def apply_missing_container(path_keys)
        key = path_keys.first
        rest = path_keys.drop(1)
        # @type var replacement_container: Array[Object] | Hash[Object, Object]
        replacement_container = array_index_key?(key) ? [] : {}
        apply_to(replacement_container, [key] + rest)
      end

      # :reek:UtilityFunction
      def array_index_key?(key)
        numeric_key?(key)
      end

      # :reek:UtilityFunction
      def numeric_key?(key)
        return true if key.is_a?(Integer)

        key.is_a?(String) && key.match?(/\A-?\d+\z/)
      end

      def invalid_index_error(key)
        message = "Invalid array index for with modifier: #{key.inspect}"
        EvaluationError.new(message, rule: nil, location: location)
      end
    end
  end
end
