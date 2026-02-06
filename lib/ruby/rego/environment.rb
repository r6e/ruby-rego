# frozen_string_literal: true

require_relative "ast"
require_relative "errors"
require_relative "value"
require_relative "builtins/registry"
require_relative "environment/overrides"
require_relative "environment/reference_resolution"

module Ruby
  module Rego
    # Execution environment for evaluating Rego policies.
    # :reek:TooManyInstanceVariables
    class Environment
      RESERVED_BINDINGS = {
        "input" => :input,
        "data" => :data
      }.freeze
      RESERVED_NAMES = RESERVED_BINDINGS.keys.freeze

      # @return [Value]
      attr_reader :input

      # @return [Value]
      attr_reader :data

      # @return [Hash]
      attr_reader :rules

      # @return [Builtins::BuiltinRegistry, Builtins::BuiltinRegistryOverlay]
      attr_reader :builtin_registry

      # @param input [Object]
      # @param data [Object]
      # @param rules [Hash]
      # @param builtin_registry [Builtins::BuiltinRegistry, Builtins::BuiltinRegistryOverlay]
      def initialize(input: {}, data: {}, rules: {}, builtin_registry: Builtins::BuiltinRegistry.instance)
        @input = Value.from_ruby(input)
        @data = Value.from_ruby(data)
        @rules = rules.dup
        @builtin_registry = builtin_registry
        @locals = [{}] # @type var locals: Array[Hash[String, Value]]
      end

      include EnvironmentOverrides
      include EnvironmentReferenceResolution

      # @return [Environment]
      def push_scope
        scope = {} # @type var scope: Hash[String, Value]
        locals << scope
        self
      end

      # @return [void]
      def pop_scope
        locals.pop if locals.length > 1
        nil
      end

      # @param name [String, Symbol]
      # @param value [Object]
      # @return [Value]
      def bind(name, value)
        name = name.to_s
        raise Error, "Cannot bind reserved name: #{name}" if RESERVED_NAMES.include?(name)

        value = Value.from_ruby(value)
        locals.last[name] = value
        value
      end

      # @param name [String, Symbol]
      # @return [Value]
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

      # @param bindings [Hash{String, Symbol => Object}]
      # @yieldreturn [Object]
      # @return [Object]
      def with_bindings(bindings)
        push_scope
        bindings.each { |name, value| bind(name, value) }
        yield
      ensure
        pop_scope
      end

      # @param registry [Builtins::BuiltinRegistry, Builtins::BuiltinRegistryOverlay]
      # @yieldparam environment [Environment]
      # @return [Object]
      def with_builtin_registry(registry)
        original = @builtin_registry
        @builtin_registry = registry
        yield self
      ensure
        @builtin_registry = original
      end

      private

      attr_reader :locals
    end
  end
end
