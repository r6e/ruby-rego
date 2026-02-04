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
          @operator = operator
          validate_operator!
          super(location: location)
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

        def validate_operator # rubocop:disable Naming/PredicateMethod
          OPERATORS.include?(@operator)
        end

        def validate_operator!
          return if validate_operator

          raise ArgumentError, "Unknown binary operator: #{@operator.inspect}"
        end
      end
    end
  end
end
