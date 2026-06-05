# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Reference-value caching.
      class ReferenceResolver
        private

        def cached_reference_value(reference)
          reference_cache&.fetch(reference, nil)
        end

        def cache_reference_value(reference, value)
          cache = reference_cache
          return unless cache

          cache[reference] = value
        end

        def reference_cache
          memoization&.context&.reference_values
        end

        def cacheable_reference?(reference)
          !static_reference_keys(reference).nil?
        end

        def static_reference_keys(reference)
          cache = memoization&.context&.reference_keys
          return StaticKeyBuilder.new(reference).call unless cache

          cached = cache.fetch(reference) do
            StaticKeyBuilder.new(reference).call || UNCACHEABLE
          end
          return nil if cached == UNCACHEABLE

          cached
        end
      end
    end
  end
end
