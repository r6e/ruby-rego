# frozen_string_literal: true

require_relative "ast"
require_relative "errors"
require_relative "value"
require_relative "builtins/registry"
require_relative "memoization"
require_relative "environment/overrides"
require_relative "environment/reference_resolution"

module Ruby
  module Rego
    # Execution environment for evaluating Rego policies.
    # :reek:TooManyInstanceVariables
    # rubocop:disable Metrics/ClassLength
    class Environment
      # Encapsulates environment state for pooling.
      State = Struct.new(:input, :data, :rules, :builtin_registry, keyword_init: true)

      RESERVED_BINDINGS = {
        "input" => :input,
        "data" => :data
      }.freeze
      RESERVED_NAMES = RESERVED_BINDINGS.keys.freeze

      # Input document as a Rego value.
      #
      # @return [Value]
      attr_reader :input

      # Data document as a Rego value.
      #
      # @return [Value]
      attr_reader :data

      # Rule index by name.
      #
      # @return [Hash]
      attr_reader :rules

      # Builtin registry in use.
      #
      # @return [Builtins::BuiltinRegistry, Builtins::BuiltinRegistryOverlay]
      attr_reader :builtin_registry

      # Memoization store for evaluation caches.
      #
      # @return [Memoization::Store]
      attr_reader :memoization

      # Create an evaluation environment.
      #
      # @param input [Object] input document
      # @param data [Object] data document
      # @param rules [Hash] rule index
      # @param builtin_registry [Builtins::BuiltinRegistry, Builtins::BuiltinRegistryOverlay] registry
      def initialize(input: {}, data: {}, rules: {}, builtin_registry: Builtins::BuiltinRegistry.instance)
        @memoization = Memoization::Store.new
        @builtin_registry = builtin_registry
        @locals = [fresh_scope] # @type var locals: Array[Hash[String, Value]]
        @scope_pool = [] # @type var @scope_pool: Array[Hash[String, Value]]
        apply_state(State.new(input: input, data: data, rules: rules, builtin_registry: builtin_registry))
      end

      # Build an environment from a state struct.
      #
      # @param state [State]
      # @return [Environment]
      def self.from_state(state)
        new(
          input: state.input,
          data: state.data,
          rules: state.rules,
          builtin_registry: state.builtin_registry
        )
      end

      include EnvironmentOverrides
      include EnvironmentReferenceResolution

      # Push a new scope for local bindings.
      #
      # @return [Environment] self
      def push_scope
        scope = scope_pool.pop
        scope ||= fresh_scope
        scope.clear
        locals << scope
        self
      end

      # Pop the latest local scope.
      #
      # @return [void]
      def pop_scope
        return nil if locals.length <= 1

        scope = locals.pop # @type var scope: Hash[String, Value]
        scope.clear
        scope_pool << scope
        nil
      end

      # Reset environment state for reuse.
      #
      # @param state [State] reset state
      # @return [Environment] self
      def reset!(state)
        apply_state(state)
        reset_scopes
        memoization.reset!
        self
      end

      # Reset environment state for reuse without mutation semantics.
      #
      # @param state [State] reset state
      # @return [Environment]
      def reset(state)
        reset!(state)
      end

      # Reset the environment for pool reuse.
      #
      # @return [Environment]
      def prepare_for_pool
        empty_hash = {} # @type var empty_hash: Hash[untyped, untyped]
        reset(State.new(input: empty_hash, data: empty_hash, rules: rules, builtin_registry: builtin_registry))
      end

      # Bind a local name to a value.
      #
      # @param name [String, Symbol] binding name
      # @param value [Object] value to bind
      # @return [Value] bound value
      def bind(name, value)
        name = name.to_s
        raise Error, "Cannot bind reserved name: #{name}" if RESERVED_NAMES.include?(name)

        value = Value.from_ruby(value)
        locals.last[name] = value
        value
      end

      # Lookup a binding from the current scope chain.
      #
      # @param name [String, Symbol] binding name
      # @return [Value] resolved value or undefined
      # :reek:TooManyStatements
      def lookup(name)
        name = name.to_s
        reserved = RESERVED_BINDINGS[name]
        return public_send(reserved) if reserved

        locals.reverse_each do |scope|
          return scope[name] if scope.key?(name)
        end

        UndefinedValue.new
      end

      # Check whether a name is bound in any local scope.
      #
      # @param name [String, Symbol] binding name
      # @return [Boolean]
      def local_bound?(name)
        name = name.to_s
        return false if RESERVED_NAMES.include?(name)

        locals.reverse_each do |scope|
          return true if scope.key?(name)
        end

        false
      end

      # Execute a block with additional temporary bindings.
      #
      # @param bindings [Hash{String, Symbol => Object}] bindings to apply
      # @yieldreturn [Object]
      # @return [Object] block result
      def with_bindings(bindings)
        push_scope
        bindings.each { |name, value| bind(name, value) }
        yield
      ensure
        pop_scope
      end

      # Execute a block with an overridden builtin registry.
      #
      # @param registry [Builtins::BuiltinRegistry, Builtins::BuiltinRegistryOverlay] registry to use
      # @yieldparam environment [Environment]
      # @return [Object] block result
      def with_builtin_registry(registry)
        original = @builtin_registry
        memoization.with_context do
          @builtin_registry = registry
          yield self
        end
      ensure
        @builtin_registry = original
      end

      private

      attr_reader :locals, :scope_pool

      def fresh_scope
        {} # @type var scope: Hash[String, Value]
      end

      def reset_scopes
        locals.each(&:clear)
        scope_pool.clear
        base_scope = locals.first || fresh_scope
        locals.replace([base_scope])
        base_scope.clear
      end

      def apply_state(state)
        @input = Value.from_ruby(state.input)
        @data = Value.from_ruby(state.data)
        @rules = state.rules.dup
        @builtin_registry = state.builtin_registry
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
end
