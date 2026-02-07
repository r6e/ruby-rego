# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents an `every` expression.
      class Every < Base
        # @param value_var [Variable]
        # @param domain [Object]
        # @param body [Array<Object>]
        # @param key_var [Variable, nil]
        # @param location [Location, nil]
        def initialize(value_var:, domain:, body:, key_var: nil, location: nil)
          super(location: location)
          @key_var = key_var
          @value_var = value_var
          @domain = domain
          @body = body.dup.freeze
        end

        # @return [Variable, nil]
        attr_reader :key_var

        # @return [Variable]
        attr_reader :value_var

        # @return [Object]
        attr_reader :domain

        # @return [Array<Object>]
        attr_reader :body
      end
    end
  end
end
