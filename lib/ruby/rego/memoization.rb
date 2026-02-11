# frozen_string_literal: true

module Ruby
  module Rego
    # Shared memoization store for evaluation caches.
    module Memoization
      # Holds per-scope caches used during evaluation.
      class Context
        def initialize
          @rule_values = {} # @type var @rule_values: Hash[String, Value]
          @reference_values = {} # @type var @reference_values: Hash[AST::Reference, Value]
          @reference_keys = {} # @type var @reference_keys: Hash[AST::Reference, Array[Object] | Object]
          @function_values = {} # @type var @function_values: Hash[Array[Object], Value]
        end

        # @return [Hash]
        attr_reader :rule_values

        # @return [Hash]
        attr_reader :reference_values

        # @return [Hash]
        attr_reader :reference_keys

        # @return [Hash]
        attr_reader :function_values
      end

      # Stack-based memoization store for nested scopes.
      class Store
        def initialize
          @contexts = [Context.new]
        end

        # Reset memoized data for a new evaluation.
        #
        # @return [void]
        def reset!
          @contexts = [Context.new]
          nil
        end

        # Reset memoized data without mutation semantics.
        #
        # @return [void]
        def reset
          reset!
        end

        # Run with a fresh memoization context.
        #
        # @return [Object]
        def with_context
          @contexts << Context.new
          yield
        ensure
          @contexts.pop
        end

        # @return [Context]
        def context
          @contexts.last
        end
      end
    end
  end
end
