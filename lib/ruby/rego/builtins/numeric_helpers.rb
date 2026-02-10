# frozen_string_literal: true

require_relative "base"
require_relative "../errors"
require_relative "../value"

module Ruby
  module Rego
    module Builtins
      # Shared numeric coercion helpers for builtins.
      module NumericHelpers
        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [Integer]
        def self.integer_value(value, context:)
          Base.assert_type(value, expected: NumberValue, context: context)
          numeric = value.value
          return numeric if numeric.is_a?(Integer)
          return numeric.to_i if numeric.is_a?(Float) && numeric.finite? && numeric.modulo(1).zero?

          raise_integer_error(numeric, context)
        end

        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [Integer]
        def self.non_negative_integer(value, context:)
          integer = integer_value(value, context: context)
          return integer if integer >= 0

          raise Ruby::Rego::BuiltinArgumentError.new(
            "Expected non-negative integer",
            expected: "non-negative integer",
            actual: integer,
            context: context,
            location: nil
          )
        end

        # @param numeric [Numeric]
        # @param context [String]
        # @return [void]
        def self.raise_integer_error(numeric, context)
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Expected integer",
            expected: "integer",
            actual: numeric,
            context: context,
            location: nil
          )
        end
        private_class_method :raise_integer_error
      end
    end
  end
end
