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

        # Sum an array or set of numbers. The OPA-faithful arithmetic (integer fast-path vs prec-64
        # big.Float fold, and the int64-overflow handling) lives in {Number.sum}; here an empty collection
        # sums to 0 and a set is deduplicated and folded in ascending order by {numeric_array}.
        #
        # @param collection [Ruby::Rego::Value] an array or set of numbers
        # @return [Ruby::Rego::Value]
        def self.sum(collection)
          numbers = numeric_array(collection, name: "sum")
          Value.from_ruby(bounded_fold(:sum, numbers))
        end

        # Multiply an array or set of numbers. The OPA-faithful arithmetic (prec-64 big.Float fold with no
        # integer fast-path) and the DoS magnitude cap live in {Number.product}; here an empty collection
        # is the multiplicative identity 1 and a set is folded in ascending order by {numeric_array}.
        #
        # @param collection [Ruby::Rego::Value] an array or set of numbers
        # @return [Ruby::Rego::Value]
        def self.product(collection)
          numbers = numeric_array(collection, name: "product")
          Value.from_ruby(bounded_fold(:product, numbers))
        end

        # Fold `numbers` via the named {Number} aggregate (`:sum` or `:product`), mapping its
        # magnitude-overflow RangeError to undefined. The rescue wraps ONLY the Number call so an
        # unexpected error from numeric_array/Value.from_ruby fails fast rather than being mislabeled
        # "overflow". Number.product raises RangeError to cap its unbounded fold; Number.sum raises only as
        # an engine-overflow totality backstop (it has no magnitude cap) — see those methods.
        #
        # @param name [Symbol] :sum or :product
        # @param numbers [Array<Numeric>]
        # @return [Ruby::Rego::Number, Integer]
        def self.bounded_fold(name, numbers)
          Number.public_send(name, numbers)
        rescue RangeError => e
          Base.raise_argument_error(
            e.message,
            expected: "#{name} within the supported magnitude range",
            actual: "magnitude overflow",
            context: name.to_s
          )
        end
        private_class_method :bounded_fold

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

        # Validate every element of `elements` is a foldable number and return their raw numeric values,
        # in the given order. {numeric_value} applies both gates ahead of the set sort {numeric_array}
        # performs, so a bad element maps to undefined rather than crashing the sort or the fold.
        #
        # @param elements [Enumerable<Ruby::Rego::Value>]
        # @param name [String]
        # @return [Array<Numeric>]
        def self.numeric_values(elements, name:)
          elements.to_a.map.with_index do |element, index|
            numeric_value(element, context: "#{name} element #{index}")
          end
        end
        private_class_method :numeric_values

        # Validate one element is a NumberValue wrapping a foldable finite-real number, returning its raw
        # numeric value. Two gates: the type check maps a non-number element (`{1, "a"}`) to undefined,
        # and {Number.finite_real?} maps a NumberValue wrapping a non-real / non-finite Ruby Numeric to
        # undefined. The latter is reachable because {Value.from_ruby} admits any Ruby Numeric (a Complex,
        # a non-finite Float/BigDecimal passed via the library `input:` API) into a NumberValue; without
        # this gate the set sort crashes on Complex's missing ordering, or the fold crashes converting it
        # — aborting the policy instead of returning undefined.
        #
        # @param element [Ruby::Rego::Value]
        # @param context [String]
        # @return [Numeric]
        def self.numeric_value(element, context:)
          Base.assert_type(element, expected: NumberValue, context: context)
          raw = element.value
          return raw if Number.finite_real?(raw)

          Base.raise_argument_error(
            "aggregate element is not a finite real number",
            expected: "finite real number",
            actual: raw.class.name,
            context: context
          )
        end
        private_class_method :numeric_value

        # @param numbers [Array<Numeric>]
        # @param name [String]
        # @return [void]
        def self.ensure_non_empty(numbers, name:)
          return unless numbers.empty?

          Base.raise_argument_error(
            "Expected a non-empty array",
            expected: "non-empty array",
            actual: numbers.size,
            context: name
          )
        end
        private_class_method :ensure_non_empty
      end
    end
  end
end

Ruby::Rego::Builtins::Aggregates.register!
