# frozen_string_literal: true

require "json"

module Ruby
  module Rego
    class Evaluator
      # Formats template string values using a stable JSON representation.
      class TemplateValueFormatter
        # @param value [Object]
        def initialize(value)
          @value = value
        end

        # @return [String]
        def render
          case value
          when NilClass then "null"
          when String then value
          when Array, Hash, Set then JSON.generate(canonical_value)
          else value.to_s
          end
        end

        # @return [Object]
        def canonical_value
          case value
          when Hash then canonicalize_hash
          when Array then canonicalize_array
          when Set then canonicalize_set
          else value
          end
        end

        private

        attr_reader :value

        def canonicalize_hash
          result = {} # @type var result: Hash[untyped, untyped]
          value.keys.sort_by(&:to_s).each do |key|
            result[key] = self.class.new(value[key]).canonical_value
          end
          result
        end

        def canonicalize_array
          value.map { |element| self.class.new(element).canonical_value }
        end

        def canonicalize_set
          value
            .to_a
            .map { |element| self.class.new(element).canonical_value }
            .sort_by { |element| JSON.generate(element) }
        end
      end
    end
  end
end
