# frozen_string_literal: true

require "json"
require_relative "error_payload"
require_relative "value"

module Ruby
  module Rego
    # Represents the outcome of evaluating a policy or expression.
    class Result
      # Evaluated value.
      #
      # @return [Value]
      attr_reader :value

      # Variable bindings captured during evaluation.
      #
      # @return [Hash{String => Value}]
      attr_reader :bindings

      # True when evaluation succeeded and produced a value.
      #
      # @return [Boolean]
      attr_reader :success

      # Errors collected during evaluation.
      #
      # @return [Array<Object>]
      attr_reader :errors

      # Create a result wrapper.
      #
      # @param value [Object] evaluation value
      # @param success [Boolean] success flag
      # @param bindings [Hash{String, Symbol => Object}] variable bindings
      # @param errors [Array<Object>] collected errors
      def initialize(value:, success:, bindings: {}, errors: [])
        @value = Value.from_ruby(value)
        @bindings = {} # @type var @bindings: Hash[String, Value]
        add_bindings(bindings)
        @success = success
        @errors = errors.dup
      end

      # Convenience success predicate.
      #
      # @return [Boolean]
      def success?
        success
      end

      # True when the value is undefined.
      #
      # @return [Boolean]
      def undefined?
        value.is_a?(UndefinedValue)
      end

      # Convert the result to a serializable hash.
      #
      # @return [Hash{Symbol => Object}]
      def to_h
        {
          value: value.to_ruby,
          bindings: bindings.transform_values(&:to_ruby),
          success: success,
          errors: errors.map { |error| ErrorPayload.from(error) }
        }
      end

      # Serialize the result as JSON.
      #
      # @param _args [Array<Object>]
      # @return [String]
      def to_json(*args)
        options = args.first
        return JSON.generate(to_h) unless options.is_a?(Hash)

        JSON.generate(to_h, options)
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
