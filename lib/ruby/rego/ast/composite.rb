# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents an array literal.
      class ArrayLiteral < Base
        # @param elements [Array<Object>]
        # @param location [Location, nil]
        def initialize(elements:, location: nil)
          super(location: location)
          @elements = elements.dup.freeze
        end

        # @return [Array<Object>]
        attr_reader :elements
      end

      # Represents an object literal.
      class ObjectLiteral < Base
        # @param pairs [Array<Array(Object, Object)>]
        # @param location [Location, nil]
        def initialize(pairs:, location: nil)
          super(location: location)
          @pairs = pairs.map { |pair| pair.dup.freeze }.freeze
        end

        # @return [Array<Array(Object, Object)>]
        attr_reader :pairs
      end

      # Represents a set literal.
      class SetLiteral < Base
        # @param elements [Array<Object>]
        # @param location [Location, nil]
        def initialize(elements:, location: nil)
          super(location: location)
          @elements = elements.dup.freeze
        end

        # @return [Array<Object>]
        attr_reader :elements
      end
    end
  end
end
