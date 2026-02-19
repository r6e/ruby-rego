# frozen_string_literal: true

require_relative "compiler"
require_relative "evaluator"
require_relative "environment_pool"
require_relative "error_handling"

module Ruby
  module Rego
    # Compiled policy for reuse across evaluations.
    class Policy
      # Create a compiled policy from source.
      #
      # @param source [String] Rego source
      # @param environment_pool [EnvironmentPool] optional pool override
      def initialize(source, environment_pool: EnvironmentPool.new)
        @source = source.to_s
        @compiled_module = Ruby::Rego.compile(@source)
        @environment_pool = environment_pool
      end

      # Evaluate the policy with the provided input and query.
      #
      # @param input [Object] input document
      # @param data [Object] data document
      # @param query [Object, nil] query path
      # @return [Result, nil] evaluation result, or nil when a query is undefined
      def evaluate(input: {}, data: {}, query: nil)
        ErrorHandling.wrap("evaluation") { evaluate_with_pool(input: input, data: data, query: query) }
      end

      private

      attr_reader :compiled_module, :environment_pool, :source

      def evaluate_with_pool(input:, data:, query:)
        state = Environment::State.new(
          input: input,
          data: data,
          rules: compiled_module.rules_by_name,
          builtin_registry: Builtins::BuiltinRegistry.instance
        )
        environment = environment_pool.checkout(state)
        Evaluator.from_environment(compiled_module, environment).evaluate(query)
      ensure
        environment_pool.checkin(environment) if environment
      end
    end
  end
end
