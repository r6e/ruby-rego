# frozen_string_literal: true

require_relative "errors"

module Ruby
  module Rego
    # Encapsulates input/data root access for with modifiers.
    class WithModifierRootScope
      ROOT_NAMES = %w[input data].freeze

      # @param environment [Environment]
      # @param name [String]
      # @param location [Location, nil]
      def initialize(environment:, name:, location: nil)
        @environment = environment
        @name = name
        @location = location
        validate_name
      end

      # @return [Object]
      def base_value
        input_scope? ? environment.input.to_ruby : environment.data.to_ruby
      end

      # @param overridden [Object]
      # @yieldparam environment [Environment]
      # @return [Object]
      def with_override(overridden, &)
        if input_scope?
          environment.with_overrides(input: overridden, &)
        else
          environment.with_overrides(data: overridden, &)
        end
      end

      private

      attr_reader :environment, :name, :location

      def input_scope?
        name == "input"
      end

      def validate_name
        return if ROOT_NAMES.include?(name)

        raise EvaluationError.new(
          "With modifier expects input or data reference",
          rule: nil,
          location: location
        )
      end
    end
  end
end
