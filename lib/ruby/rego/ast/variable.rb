# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents a variable identifier.
      class Variable < Base
        # @param name [String]
        # @param location [Location, nil]
        def initialize(name:, location: nil)
          super(location: location)
          @name = name
        end

        # @return [String]
        attr_reader :name
      end
    end
  end
end
