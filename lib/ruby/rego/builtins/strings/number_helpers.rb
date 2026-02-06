# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        def self.integer_value(value, context:)
          Base.assert_type(value, expected: NumberValue, context: context)
          numeric = value.value
          return numeric if numeric.is_a?(Integer)
          return numeric.to_i if numeric.is_a?(Float) && numeric.finite? && numeric.modulo(1).zero?

          raise_integer_error(numeric, context)
        end
        private_class_method :integer_value

        def self.non_negative_integer(value, context:)
          integer = integer_value(value, context: context)
          return integer if integer >= 0

          raise Ruby::Rego::TypeError.new(
            "Expected non-negative integer",
            expected: "non-negative integer",
            actual: integer,
            context: context,
            location: nil
          )
        end
        private_class_method :non_negative_integer

        def self.ensure_base(base_value)
          return if base_value.between?(2, 36)

          raise Ruby::Rego::TypeError.new(
            "Invalid base",
            expected: "base between 2 and 36",
            actual: base_value,
            context: "format_int",
            location: nil
          )
        end
        private_class_method :ensure_base

        def self.raise_integer_error(numeric, context)
          raise Ruby::Rego::TypeError.new(
            "Expected integer",
            expected: "integer",
            actual: numeric,
            context: context,
            location: nil
          )
        end
        private_class_method :raise_integer_error

        def self.base_encode(number_value, base_value)
          return "0" if number_value.zero?

          prefix = negative_prefix(number_value)
          encoded = encode_digits(number_value.abs, base_value)
          "#{prefix}#{encoded}"
        end
        private_class_method :base_encode

        def self.negative_prefix(number_value)
          number_value.negative? ? "-" : ""
        end
        private_class_method :negative_prefix

        def self.encode_digits(remaining, base_value)
          digits = [] # @type var digits: Array[String]
          while remaining.positive?
            digits << BASE_DIGITS.fetch(remaining % base_value)
            remaining /= base_value
          end

          digits.reverse.join
        end
        private_class_method :encode_digits
      end
    end
  end
end
