# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents a function or built-in call.
      class Call < Base
        # @param name [Object]
        # @param args [Array<Object>]
        # @param location [Location, nil]
        def initialize(name:, args:, location: nil)
          super(location: location)
          @name = name
          @args = args.dup.freeze
        end

        # @return [Object]
        attr_reader :name

        # @return [Array<Object>]
        attr_reader :args
      end
    end
  end
end
