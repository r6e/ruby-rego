# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents a query literal with optional with modifiers.
      class QueryLiteral < Base
        # @param expression [Object]
        # @param with_modifiers [Array<WithModifier>]
        # @param location [Location, nil]
        def initialize(expression:, with_modifiers: [], location: nil)
          super(location: location)
          @expression = expression
          @with_modifiers = with_modifiers.dup.freeze
        end

        # @return [Object]
        attr_reader :expression

        # @return [Array<WithModifier>]
        attr_reader :with_modifiers
      end

      # Represents a `some` declaration.
      class SomeDecl < Base
        # @param variables [Array<Variable>]
        # @param collection [Object, nil]
        # @param location [Location, nil]
        def initialize(variables:, collection: nil, location: nil)
          super(location: location)
          @variables = variables.dup.freeze
          @collection = collection
        end

        # @return [Array<Variable>]
        attr_reader :variables

        # @return [Object, nil]
        attr_reader :collection
      end

      # Represents a `with` modifier.
      class WithModifier < Base
        # @param target [Object]
        # @param value [Object]
        # @param location [Location, nil]
        def initialize(target:, value:, location: nil)
          super(location: location)
          @target = target
          @value = value
        end

        # @return [Object]
        attr_reader :target

        # @return [Object]
        attr_reader :value
      end
    end
  end
end
