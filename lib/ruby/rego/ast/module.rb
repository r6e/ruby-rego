# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents a complete Rego module.
      class Module < Base
        # @param package [Package]
        # @param imports [Array<Import>]
        # @param rules [Array<Rule>]
        # @param location [Location, nil]
        def initialize(package:, imports:, rules:, location: nil)
          super(location: location)
          @package = package
          @imports = imports
          @rules = rules
        end

        # @return [Package]
        attr_reader :package

        # @return [Array<Import>]
        attr_reader :imports

        # @return [Array<Rule>]
        attr_reader :rules
      end
    end
  end
end
