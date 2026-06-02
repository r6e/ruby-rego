# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

module Ruby
  module Rego
    module Builtins
      # Built-in numeric helpers (abs, round, ceil, floor, numbers.range).
      module Numbers
        extend RegistryHelpers

        NUMBER_FUNCTIONS = {
          "abs" => { arity: 1, handler: :abs },
          "round" => { arity: 1, handler: :round },
          "ceil" => { arity: 1, handler: :ceil },
          "floor" => { arity: 1, handler: :floor },
          "numbers.range" => { arity: 2, handler: :range }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, NUMBER_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.abs(value)
          NumberValue.new(numeric(value, "abs").abs)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.round(value)
          NumberValue.new(numeric(value, "round").round)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.ceil(value)
          NumberValue.new(numeric(value, "ceil").ceil)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.floor(value)
          NumberValue.new(numeric(value, "floor").floor)
        end

        # Inclusive integer range, ascending or descending.
        #
        # Matches OPA: integer-valued floats (e.g. 3.0) are accepted as bounds,
        # while a non-integer bound (e.g. 1.5) yields an undefined result.
        #
        # @param start_value [Ruby::Rego::Value]
        # @param end_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue, Ruby::Rego::UndefinedValue]
        def self.range(start_value, end_value)
          start_bound = integer_bound(start_value, "numbers.range")
          end_bound = integer_bound(end_value, "numbers.range")
          return UndefinedValue.new unless start_bound && end_bound

          ArrayValue.new(range_elements(start_bound, end_bound).map { |number| NumberValue.new(number) })
        end

        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [Numeric]
        def self.numeric(value, context)
          Base.assert_type(value, expected: NumberValue, context: context)
          value.value
        end
        private_class_method :numeric

        # Returns the integer value of a numeric bound, or nil when it is not an
        # integer value (a fractional float, infinity, or NaN).
        #
        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [Integer, nil]
        def self.integer_bound(value, context)
          number = numeric(value, context)
          return number if number.is_a?(Integer)
          return number.to_i if number.is_a?(Float) && number.finite? && (number % 1).zero?

          nil
        end
        private_class_method :integer_bound

        # @param start_bound [Integer]
        # @param end_bound [Integer]
        # @return [Array<Integer>]
        def self.range_elements(start_bound, end_bound)
          return (start_bound..end_bound).to_a if start_bound <= end_bound

          start_bound.downto(end_bound).to_a
        end
        private_class_method :range_elements
      end
    end
  end
end

Ruby::Rego::Builtins::Numbers.register!
