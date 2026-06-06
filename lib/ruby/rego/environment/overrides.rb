# frozen_string_literal: true

require_relative "../value"

module Ruby
  module Rego
    # Provides temporary input/data overrides for the environment.
    module EnvironmentOverrides
      UNSET = Object.new.freeze

      # @param input [Object]
      # @param data [Object]
      # @param data_paths [Array<Array<String>>] data key-paths shadowed by this
      #   override, so a rule at the path resolves to the override, not its value.
      # @yieldparam environment [Environment]
      # @return [Object]
      def with_overrides(input: UNSET, data: UNSET, data_paths: [])
        original = [@input, @data, @overridden_data_paths]
        memoization.with_context do
          apply_overrides(input, data)
          @overridden_data_paths += data_paths
          yield self
        end
      ensure
        @input, @data, @overridden_data_paths = original
      end

      private

      def apply_overrides(input, data)
        @input = Value.from_ruby(input) unless input.equal?(UNSET)
        @data = Value.from_ruby(data) unless data.equal?(UNSET)
      end
    end
  end
end
