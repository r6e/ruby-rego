# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents a reference to nested data (e.g. input.user.roles[0]).
      class Reference < Base
        # @param base [Object]
        # @param path [Array<RefArg>]
        # @param location [Location, nil]
        def initialize(base:, path:, location: nil)
          super(location: location)
          @base = base
          @path = path.dup.freeze
        end

        # @return [Object]
        attr_reader :base

        # @return [Array<RefArg>]
        attr_reader :path
      end

      # Base class for reference path arguments.
      class RefArg < Base
        # @param value [Object]
        # @param location [Location, nil]
        def initialize(value:, location: nil)
          super(location: location)
          @value = value
        end

        # @return [Object]
        attr_reader :value
      end

      # Dot-based reference argument (e.g. .foo).
      class DotRefArg < RefArg
        # @param value [Object]
        # @param location [Location, nil]
        def initialize(value:, location: nil)
          super
        end
      end

      # Bracket-based reference argument (e.g. [0]).
      class BracketRefArg < RefArg
        # @param value [Object]
        # @param location [Location, nil]
        def initialize(value:, location: nil)
          super
        end
      end
    end
  end
end
