# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents a package declaration.
      class Package < Base
        # @param path [Array<String>]
        # @param location [Location, nil]
        def initialize(path:, location: nil)
          super(location: location)
          @path = path
        end

        # @return [Array<String>]
        attr_reader :path
      end
    end
  end
end
