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
          @operator = operator
          validate_operator!
          super(location: location)
          @operand = operand
        end

        # @return [Symbol]
        attr_reader :operator

        # @return [Object]
        attr_reader :operand

        private

        def validate_operator # rubocop:disable Naming/PredicateMethod
          OPERATORS.include?(@operator)
        end

        def validate_operator!
          return if validate_operator

          raise ArgumentError, "Unknown unary operator: #{@operator.inspect}"
        end
      end
    end
  end
end
