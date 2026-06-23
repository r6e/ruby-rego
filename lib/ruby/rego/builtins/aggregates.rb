# frozen_string_literal: true

require_relative "base"
require_relative "registry"

module Ruby
  module Rego
    module Builtins
      # Built-in aggregation helpers.
      module Aggregates
        AGGREGATE_FUNCTIONS = {
          "count" => :count,
          "sum" => :sum,
          "max" => :max,
          "min" => :min,
          "all" => :all,
          "any" => :any
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance

          AGGREGATE_FUNCTIONS.each do |name, handler|
            register_function(registry, name, handler)
          end

          registry
        end

        def self.register_function(registry, name, handler)
          return if registry.registered?(name)

          registry.register(name, 1) { |value| public_send(handler, value) }
        end
        private_class_method :register_function

        # @param collection [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.count(collection)
          Base.assert_type(
            collection,
            expected: [ArrayValue, ObjectValue, SetValue, StringValue],
            context: "count"
          )

          NumberValue.new(collection.value.size)
        end

        # @param array [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.sum(array)
          numbers = numeric_array(array, name: "sum")
          # Sum of raw input Floats can overflow to a non-finite Float (e.g. [1e308, 1e308]); Value.from_ruby
          # maps that to undefined at the boundary instead of letting it crash serialization.
          Value.from_ruby(numbers.sum)
        end

        # @param array [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        def self.max(array)
          numbers = numeric_array(array, name: "max")
          ensure_non_empty(numbers, name: "max")
          # Among value-equal extrema OPA returns the LAST element (so max([1.50, 1.5]) -> 1.5, keeping
          # the later spelling). A single-pass reduce keeping the later element on a tie (the explicit
          # `>=` documents the tie-break) avoids the reversed-array copy that `reverse.max` would allocate.
          # rubocop:disable Style/MinMaxComparison
          Value.from_ruby(numbers.reduce { |best, number| number >= best ? number : best })
          # rubocop:enable Style/MinMaxComparison
        end

        # @param array [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        def self.min(array)
          numbers = numeric_array(array, name: "min")
          ensure_non_empty(numbers, name: "min")
          # OPA returns the LAST element among value-equal minima too; reduce keeping the later element
          # on a tie (single pass, no reversed-array copy).
          # rubocop:disable Style/MinMaxComparison
          Value.from_ruby(numbers.reduce { |best, number| number <= best ? number : best })
          # rubocop:enable Style/MinMaxComparison
        end

        # @param array [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.all(array)
          Base.assert_type(array, expected: ArrayValue, context: "all")
          BooleanValue.new(array.value.all?(&:truthy?))
        end

        # @param array [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.any(array)
          Base.assert_type(array, expected: ArrayValue, context: "any")
          BooleanValue.new(array.value.any?(&:truthy?))
        end

        # @param array [Ruby::Rego::Value]
        # @param name [String]
        # @return [Array<Numeric>]
        def self.numeric_array(array, name:)
          Base.assert_type(array, expected: ArrayValue, context: name)

          array.value.map.with_index do |element, index|
            Base.assert_type(
              element,
              expected: NumberValue,
              context: "#{name} element #{index}"
            )
            element.value
          end
        end
        private_class_method :numeric_array

        # @param numbers [Array<Numeric>]
        # @param name [String]
        # @return [void]
        def self.ensure_non_empty(numbers, name:)
          return unless numbers.empty?

          raise Ruby::Rego::BuiltinArgumentError.new(
            "Expected a non-empty array",
            expected: "non-empty array",
            actual: numbers.size,
            context: name,
            location: nil
          )
        end
        private_class_method :ensure_non_empty
      end
    end
  end
end

Ruby::Rego::Builtins::Aggregates.register!
