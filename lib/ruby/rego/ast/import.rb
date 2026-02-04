# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents an import declaration.
      class Import < Base
        # @param path [Object]
        # @param alias_name [String, nil]
        # @param location [Location, nil]
        def initialize(path:, alias_name: nil, location: nil)
          super(location: location)
          @path = path
          @alias = alias_name
        end

        # @return [Object]
        attr_reader :path

        # @return [String, nil]
        attr_reader :alias

        # @return [String, nil]
        def alias_name
          self.alias
        end
      end
    end
  end
end
