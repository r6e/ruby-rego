# frozen_string_literal: true

require_relative "ast"
require_relative "errors"
require_relative "value"

module Ruby
  module Rego
    # Execution environment for evaluating Rego policies.
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

      # @param input [Object]
      # @param data [Object]
      # @param rules [Hash]
      def initialize(input: {}, data: {}, rules: {})
        @input = Value.from_ruby(input)
        @data = Value.from_ruby(data)
        @rules = rules.dup
        initial_scope = {} # @type var initial_scope: Hash[String, Value]
        @locals = [initial_scope]
      end

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

      # @param ref [Object]
      # @return [Value]
      # :reek:FeatureEnvy
      def resolve_reference(ref)
        base, path = if ref.is_a?(AST::Reference)
                       [ref.base, ref.path]
                     else
                       path = [] # @type var path: Array[AST::RefArg]
                       [ref, path]
                     end
        resolve_reference_path(resolve_base(base), path)
      end

      # @param variable [AST::Variable]
      # @return [Object]
      def reference_key_for(variable)
        resolve_reference_variable(variable)
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

      private

      attr_reader :locals

      # :reek:TooManyStatements
      # :reek:FeatureEnvy
      def resolve_base(base)
        return lookup(base.name) if base.is_a?(AST::Variable)
        return base if base.is_a?(Value)
        return lookup(base.to_s) if base.is_a?(String) || base.is_a?(Symbol)

        value = base.is_a?(AST::Literal) ? base.value : base
        Value.from_ruby(value)
      rescue ArgumentError
        UndefinedValue.new
      end

      # :reek:FeatureEnvy
      def resolve_path_segment(current, segment)
        key = extract_reference_key(segment)
        return UndefinedValue.new if key.is_a?(UndefinedValue)

        return current.fetch(key) if current.is_a?(ObjectValue)
        return current.fetch_index(key) if current.is_a?(ArrayValue)

        UndefinedValue.new
      end

      # :reek:FeatureEnvy
      def resolve_reference_path(current, path)
        path.each do |segment|
          current = resolve_path_segment(current, segment)
          return current if current.is_a?(UndefinedValue)
        end
        current
      end

      # :reek:TooManyStatements
      # :reek:FeatureEnvy
      def extract_reference_key(segment)
        value = segment.is_a?(AST::RefArg) ? segment.value : segment
        return value.value if value.is_a?(AST::Literal)
        return resolve_reference_variable(value) if value.is_a?(AST::Variable)
        return value.to_ruby if value.is_a?(Value)

        Value.from_ruby(value).to_ruby
      rescue ArgumentError
        UndefinedValue.new
      end

      # :reek:FeatureEnvy
      def resolve_reference_variable(value)
        resolved = lookup(value.name)
        return resolved if resolved.is_a?(UndefinedValue)

        resolved.to_ruby
      end
    end
  end
end
