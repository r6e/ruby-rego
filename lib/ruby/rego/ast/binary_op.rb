# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents a binary operation.
      class BinaryOp < Base
        OPERATORS = %i[
          eq
          neq
          lt
          lte
          gt
          gte
          plus
          minus
          mult
          div
          mod
          and
          or
          assign
          unify
        ].freeze

        # @param operator [Symbol]
        # @param left [Object]
        # @param right [Object]
        # @param location [Location, nil]
        def initialize(operator:, left:, right:, location: nil)
          validate_operator!(operator)
          super(location: location)
          @operator = operator
          @left = left
          @right = right
        end

        # @return [Symbol]
        attr_reader :operator

        # @return [Object]
        attr_reader :left

        # @return [Object]
        attr_reader :right

        private

        def validate_operator!(operator)
          return if OPERATORS.include?(operator)

          raise ArgumentError, "Unknown binary operator: #{operator.inspect}"
        end
      end
    end
  end
end
