# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # OPA's canonical term ordering, shared by the builtins that serialize a Rego set
      # deterministically (json.marshal, yaml.marshal). Rego sets are unordered; OPA emits
      # their elements sorted by term order: null < bool < number < string < array < object
      # < set. Composites compare element-wise (a nested set ranks as a set, above an object
      # — not as its array form), so the comparator runs on the raw value before any
      # JSON/YAML conversion that would flatten sets into arrays.
      module TermOrder
        # Returns a set's elements sorted into term order.
        # @param set [Set, Array]
        # @return [Array<Object>]
        def self.sorted(set)
          set.to_a.sort_by { |element| sort_key(element) }
        end

        # A comparable sort key encoding the term-order rank then the value (composites
        # recurse). NaN sorts here raise ArgumentError (NaN <=> x is nil); callers map that
        # to undefined, since a non-finite number is not serializable anyway.
        # @return [Array<Object>]
        # rubocop:disable Metrics/CyclomaticComplexity
        def self.sort_key(element)
          case element
          when false then [1, 0]
          when true then [1, 1]
          when Numeric then [2, element]
          when String then [3, element]
          when Array then [4, element.map { |item| sort_key(item) }]
          when Hash then [5, key_pairs(element)]
          when Set then [6, sorted(element).map { |item| sort_key(item) }]
          else [0, 0] # null
          end
        end
        # rubocop:enable Metrics/CyclomaticComplexity
        private_class_method :sort_key

        # Computes each key/value sort tuple once, then sorts by the key tuple — avoiding a
        # second sort_key(key) pass while sorting.
        # @return [Array<Object>]
        def self.key_pairs(hash)
          hash.map { |key, value| [sort_key(key), sort_key(value)] }.sort_by(&:first)
        end
        private_class_method :key_pairs
      end
    end
  end
end
