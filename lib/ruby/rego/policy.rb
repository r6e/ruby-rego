# frozen_string_literal: true

require_relative "compiler"
require_relative "evaluator"
require_relative "error_handling"

module Ruby
  module Rego
    # Compiled policy for reuse across evaluations.
    class Policy
      # @param source [String]
      def initialize(source)
        @source = source.to_s
        @compiled_module = Ruby::Rego.compile(@source)
      end

      # @param input [Object]
      # @param data [Object]
      # @param query [Object, nil]
      # @return [Result]
      def evaluate(input: {}, data: {}, query: nil)
        ErrorHandling.wrap("evaluation") do
          Evaluator.new(compiled_module, input: input, data: data).evaluate(query)
        end
      end

      private

      attr_reader :compiled_module, :source
    end
  end
end
