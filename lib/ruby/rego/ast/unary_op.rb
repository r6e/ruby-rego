# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents a unary operation (e.g. negation).
      class UnaryOp < Base
        OPERATORS = %i[not minus].freeze

        # @param operator [Symbol]
        # @param operand [Object]
        # @param location [Location, nil]
        def initialize(operator:, operand:, location: nil)
          validate_operator!(operator)
          super(location: location)
          @operator = operator
          @operand = operand
        end

        # @return [Symbol]
        attr_reader :operator

        # @return [Object]
        attr_reader :operand

        private

        def validate_operator!(operator)
          return if OPERATORS.include?(operator)

          raise ArgumentError, "Unknown unary operator: #{operator.inspect}"
        end
      end
    end
  end
end
