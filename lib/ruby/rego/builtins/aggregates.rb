# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "../number"

module Ruby
  module Rego
    module Builtins
      # Built-in aggregation helpers.
      module Aggregates
        AGGREGATE_FUNCTIONS = {
          "count" => :count,
          "sum" => :sum,
          "product" => :product,
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

        # @param collection [Ruby::Rego::Value] an array or set of numbers
        # @return [Ruby::Rego::NumberValue]
        def self.sum(collection)
          numbers = numeric_array(collection, name: "sum")
          # Sum of raw input Floats can overflow to a non-finite Float (e.g. [1e308, 1e308]); Value.from_ruby
          # maps that to undefined at the boundary instead of letting it crash serialization.
          Value.from_ruby(numbers.sum)
        end

        # OPA's `product` folds every element through a big.Float at precision 64 (no integer
        # fast-path), so even an all-integer product is the prec-64-rounded value and an empty
        # collection is the multiplicative identity 1. Delegated to {Number.product}, which keeps the
        # accumulator in big.Float space across the whole fold to match OPA byte-for-byte.
        #
        # @param collection [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        def self.product(collection)
          numbers = numeric_array(collection, name: "product")
          Value.from_ruby(bounded_product(numbers))
        end

        # Fold `numbers` via {Number.product}, mapping its magnitude-overflow RangeError to undefined.
        # The rescue wraps ONLY the Number.product call — Number.product raises RangeError when an
        # intermediate trips the engine's ENGINE_EMAX overflow trap or the final result would materialize
        # past MAX_MAGNITUDE_EXPONENT, both reachable only by multiplying enormous magnitudes far beyond
        # any real policy value. numeric_array (already validated) and Value.from_ruby are deliberately
        # OUTSIDE it, so an unexpected error from them fails fast rather than being mislabeled "overflow".
        #
        # @param numbers [Array<Numeric>]
        # @return [Numeric]
        def self.bounded_product(numbers)
          Number.product(numbers)
        rescue RangeError => e
          Base.raise_argument_error(
            e.message,
            expected: "product within the supported magnitude range",
            actual: "magnitude overflow",
            context: "product"
          )
        end
        private_class_method :bounded_product

        # @param collection [Ruby::Rego::Value] an array or set of numbers
        # @return [Ruby::Rego::Value]
        def self.max(collection)
          numbers = numeric_array(collection, name: "max")
          ensure_non_empty(numbers, name: "max")
          # Among value-equal extrema OPA returns the LAST element (so max([1.50, 1.5]) -> 1.5, keeping
          # the later spelling). A single-pass reduce keeping the later element on a tie (the explicit
          # `>=` documents the tie-break) avoids the reversed-array copy that `reverse.max` would allocate.
          # rubocop:disable Style/MinMaxComparison
          Value.from_ruby(numbers.reduce { |best, number| number >= best ? number : best })
          # rubocop:enable Style/MinMaxComparison
        end

        # @param collection [Ruby::Rego::Value] an array or set of numbers
        # @return [Ruby::Rego::Value]
        def self.min(collection)
          numbers = numeric_array(collection, name: "min")
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

        # Extract the numeric values of an array OR set — the two collection types OPA's numeric
        # aggregates (sum/product/max/min) accept. A set is returned in OPA's iteration order
        # (ascending by value), but only AFTER every element is validated as a number, so a mixed-type
        # set such as `{1, "a"}` raises the same element-type error (mapped to undefined) OPA does
        # rather than a Comparable crash mid-sort. An array keeps its given order.
        #
        # @param collection [Ruby::Rego::Value]
        # @param name [String]
        # @return [Array<Numeric>]
        def self.numeric_array(collection, name:)
          Base.assert_type(collection, expected: [ArrayValue, SetValue], context: name)

          numbers = numeric_values(collection.value, name: name)
          collection.is_a?(SetValue) ? numbers.sort : numbers
        end
        private_class_method :numeric_array

        # Validate every element of `elements` is a number and return their raw numeric values, in the
        # given order. {numeric_array} calls this before sorting a set, so the element-type check (which
        # maps `{1, "a"}` to undefined) runs ahead of the sort that would otherwise crash on it.
        #
        # @param elements [Enumerable<Ruby::Rego::Value>]
        # @param name [String]
        # @return [Array<Numeric>]
        def self.numeric_values(elements, name:)
          elements.to_a.map.with_index do |element, index|
            Base.assert_type(element, expected: NumberValue, context: "#{name} element #{index}")
            element.value
          end
        end
        private_class_method :numeric_values

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
