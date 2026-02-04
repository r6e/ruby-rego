# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Base class for literal values.
      class Literal < Base
        # @param value [Object]
        # @param location [Location, nil]
        def initialize(value:, location: nil)
          super(location: location)
          @value = value
        end

        # @return [Object]
        attr_reader :value
      end

      # Represents a string literal.
      class StringLiteral < Literal
        # @param value [String]
        # @param location [Location, nil]
        def initialize(value:, location: nil)
          super
        end
      end

      # Represents a numeric literal.
      class NumberLiteral < Literal
        # @param value [Numeric]
        # @param location [Location, nil]
        def initialize(value:, location: nil)
          super
        end
      end

      # Represents a boolean literal.
      class BooleanLiteral < Literal
        # @param value [Boolean]
        # @param location [Location, nil]
        def initialize(value:, location: nil)
          super
        end
      end

      # Represents a null literal.
      class NullLiteral < Literal
        # @param location [Location, nil]
        def initialize(location: nil)
          super(value: nil, location: location)
        end
      end
    end
  end
end
