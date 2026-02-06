# frozen_string_literal: true

require_relative "../value"

module Ruby
  module Rego
    # Provides temporary input/data overrides for the environment.
    module EnvironmentOverrides
      UNSET = Object.new.freeze

      # @param input [Object]
      # @param data [Object]
      # @yieldparam environment [Environment]
      # @return [Object]
      def with_overrides(input: UNSET, data: UNSET)
        original = [@input, @data]
        apply_overrides(input, data)
        yield self
      ensure
        @input, @data = original
      end

      private

      def apply_overrides(input, data)
        @input = Value.from_ruby(input) unless input.equal?(UNSET)
        @data = Value.from_ruby(data) unless data.equal?(UNSET)
      end
    end
  end
end
