# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Static reference-key construction.
      class ReferenceResolver
        # Builds static reference keys for cacheable references.
        class StaticKeyBuilder
          ROOT_NAMES = %w[input data].freeze

          # @param reference [AST::Reference]
          def initialize(reference)
            @reference = reference
          end

          # @return [Array<Object>, nil]
          def call
            base = reference.base
            return nil unless base.is_a?(AST::Variable)
            return nil unless ROOT_NAMES.include?(base.name)

            keys = [] # @type var keys: Array[Object]
            reference.path.each do |segment|
              key = segment_key(segment)
              return nil unless key

              keys << key
            end
            keys
          end

          private

          attr_reader :reference

          def segment_key(segment)
            value = segment.is_a?(AST::RefArg) ? segment.value : segment
            return value.value if value.is_a?(AST::Literal)
            return value.to_ruby if value.is_a?(Value)
            return value if value.is_a?(String) || value.is_a?(Symbol) || value.is_a?(Numeric)

            nil
          end
        end
      end
    end
  end
end
