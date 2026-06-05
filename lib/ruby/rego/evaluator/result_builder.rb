# frozen_string_literal: true

module Ruby
  module Rego
    # Builds result objects from evaluation outputs.
    class ResultBuilder
      def initialize(value, bindings)
        @value = value
        @bindings = bindings
      end

      def build
        success = !value.is_a?(UndefinedValue)
        return Result.new(value: value, success: success) unless bindings

        Result.new(value: value, success: success, bindings: bindings)
      end

      private

      attr_reader :bindings, :value
    end
  end
end
