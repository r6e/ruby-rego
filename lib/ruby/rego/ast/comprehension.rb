# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents an array comprehension.
      class ArrayComprehension < Base
        # @param term [Object]
        # @param body [Array<Object>]
        # @param location [Location, nil]
        def initialize(term:, body:, location: nil)
          super(location: location)
          @term = term
          @body = body.dup.freeze
        end

        # @return [Object]
        attr_reader :term

        # @return [Object]
        attr_reader :body
      end

      # Represents an object comprehension.
      class ObjectComprehension < Base
        # @param term [Object]
        # @param body [Array<Object>]
        # @param location [Location, nil]
        def initialize(term:, body:, location: nil)
          super(location: location)
          @term = term
          @body = body.dup.freeze
        end

        # @return [Object]
        attr_reader :term

        # @return [Object]
        attr_reader :body
      end

      # Represents a set comprehension.
      class SetComprehension < Base
        # @param term [Object]
        # @param body [Array<Object>]
        # @param location [Location, nil]
        def initialize(term:, body:, location: nil)
          super(location: location)
          @term = term
          @body = body.dup.freeze
        end

        # @return [Object]
        attr_reader :term

        # @return [Object]
        attr_reader :body
      end
    end
  end
end
