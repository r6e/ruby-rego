# frozen_string_literal: true

require_relative "../base"
require_relative "../../errors"
require_relative "../../value"

module Ruby
  module Rego
    module Builtins
      module Collections
        # Array-focused collection helpers.
        module ArrayOps
          # @param array [Ruby::Rego::Value]
          # @return [Ruby::Rego::ArrayValue]
          def self.sort(array)
            elements = array_values(array, name: "sort")
            return ArrayValue.new([]) if elements.empty?

            ensure_uniform_sort_type(elements)
            sorted = elements.sort_by(&:to_ruby)
            ArrayValue.new(sorted)
          end

          # @param left [Ruby::Rego::Value]
          # @param right [Ruby::Rego::Value]
          # @return [Ruby::Rego::ArrayValue]
          def self.array_concat(left, right)
            left_values = array_values(left, name: "array.concat left")
            right_values = array_values(right, name: "array.concat right")
            ArrayValue.new(left_values + right_values)
          end

          # @param array [Ruby::Rego::Value]
          # @param start [Ruby::Rego::Value]
          # @param stop [Ruby::Rego::Value]
          # @return [Ruby::Rego::ArrayValue]
          def self.array_slice(array, start, stop)
            elements = array_values(array, name: "array.slice array")
            start_index, stop_index = slice_indices(start, stop)
            ArrayValue.new(slice_elements(elements, start_index, stop_index))
          end

          def self.array_values(value, name:)
            Base.assert_type(value, expected: ArrayValue, context: name)
            value.value
          end
          private_class_method :array_values

          def self.ensure_uniform_sort_type(elements)
            type = sort_type(elements)
            elements.drop(1).each_with_index do |element, index|
              validate_sort_element(element, type, index + 1)
            end
          end
          private_class_method :ensure_uniform_sort_type

          def self.sort_type(elements)
            first = elements.first
            Base.assert_type(first, expected: [NumberValue, StringValue], context: "sort element 0")
            first.class
          end
          private_class_method :sort_type

          def self.validate_sort_element(element, type, index)
            Base.assert_type(element, expected: [NumberValue, StringValue], context: "sort element #{index}")
            return if element.is_a?(type)

            raise_sort_type_error(type, element.class)
          end
          private_class_method :validate_sort_element

          def self.raise_sort_type_error(expected_type, actual_type)
            raise Ruby::Rego::TypeError.new(
              "Mixed types cannot be sorted",
              expected: expected_type.name,
              actual: actual_type.name,
              context: "sort",
              location: nil
            )
          end
          private_class_method :raise_sort_type_error

          def self.slice_indices(start, stop)
            [
              non_negative_integer(start, context: "array.slice start"),
              non_negative_integer(stop, context: "array.slice stop")
            ]
          end
          private_class_method :slice_indices

          def self.slice_elements(elements, start_index, stop_index)
            length = stop_index - start_index
            return [] if length <= 0 || start_index >= elements.length

            elements.slice(start_index, length) || []
          end
          private_class_method :slice_elements

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

          def self.integer_value(value, context:)
            Base.assert_type(value, expected: NumberValue, context: context)
            numeric = value.value
            return numeric if numeric.is_a?(Integer)
            return numeric.to_i if numeric.is_a?(Float) && numeric.finite? && numeric.modulo(1).zero?

            raise_integer_error(numeric, context)
          end
          private_class_method :integer_value

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
        end
      end
    end
  end
end
