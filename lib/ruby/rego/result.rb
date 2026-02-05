# frozen_string_literal: true

require_relative "value"

module Ruby
  module Rego
    # Represents the outcome of evaluating a policy or expression.
    class Result
      # @return [Value]
      attr_reader :value

      # @return [Hash{String => Value}]
      attr_reader :bindings

      # @return [Boolean]
      attr_reader :success

      # @return [Array<Object>]
      attr_reader :errors

      # @param value [Object]
      # @param success [Boolean]
      # @param bindings [Hash{String, Symbol => Object}]
      # @param errors [Array<Object>]
      def initialize(value:, success:, bindings: {}, errors: [])
        @value = Value.from_ruby(value)
        @bindings = {} # @type var @bindings: Hash[String, Value]
        add_bindings(bindings)
        @success = success
        @errors = errors.dup
      end

      # @return [Boolean]
      def success?
        success
      end

      # @return [Boolean]
      def undefined?
        value.is_a?(UndefinedValue)
      end

      # @return [Hash{Symbol => Object}]
      def to_h
        {
          value: value.to_ruby,
          bindings: bindings.transform_values(&:to_ruby),
          success: success,
          errors: errors
        }
      end

      private

      def add_bindings(bindings)
        bindings.each do |(name, binding_value)|
          @bindings[name.to_s] = Value.from_ruby(binding_value)
        end
      end
    end
  end
end
