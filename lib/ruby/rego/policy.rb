# frozen_string_literal: true

require_relative "compiler"
require_relative "evaluator"
require_relative "error_handling"

module Ruby
  module Rego
    # Compiled policy for reuse across evaluations.
    class Policy
      # Create a compiled policy from source.
      #
      # @param source [String] Rego source
      def initialize(source)
        @source = source.to_s
        @compiled_module = Ruby::Rego.compile(@source)
      end

      # Evaluate the policy with the provided input and query.
      #
      # @param input [Object] input document
      # @param data [Object] data document
      # @param query [Object, nil] query path
      # @return [Result] evaluation result
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
