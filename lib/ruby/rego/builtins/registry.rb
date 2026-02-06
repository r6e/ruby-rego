# frozen_string_literal: true

require_relative "base"
require_relative "../errors"
require_relative "../value"

module Ruby
  module Rego
    module Builtins
      # Shared builtin invocation helpers.
      module BuiltinInvocation
        private

        def normalize_name(name)
          normalized = name.to_s
          raise ArgumentError, "Builtin name cannot be empty" if normalized.strip.empty?

          normalized
        end

        # :reek:FeatureEnvy
        def invoke_entry(entry, args)
          entry_name = entry.name
          args = ensure_array_args(args, entry_name)
          Builtins::Base.assert_arity(args, entry.arity, name: entry_name)
          Value.from_ruby(entry.handler.call(*args.map { |arg| Value.from_ruby(arg) }))
        end

        # :reek:FeatureEnvy
        def ensure_array_args(args, builtin_name)
          return args if args.is_a?(Array)

          raise Ruby::Rego::TypeError.new(
            "Expected arguments to be an Array",
            expected: Array,
            actual: args.class,
            context: "builtin #{builtin_name}",
            location: nil
          )
        end
      end

      # Registry for built-in function implementations.
      class BuiltinRegistry
        include BuiltinInvocation

        # Represents a registered built-in definition.
        Entry = Struct.new(:name, :arity, :handler, keyword_init: true)

        # @return [BuiltinRegistry]
        def self.instance
          @instance ||= new
        end

        private_class_method :new

        def initialize
          @builtins = {}
        end

        # @param name [String, Symbol]
        # @param arity [Integer]
        # @yieldparam args [Array<Ruby::Rego::Value>]
        # @return [void]
        def register(name, arity, &block)
          raise ArgumentError, "Builtin registration requires a block" unless block

          builtin_name = normalize_name(name)
          validate_arity(arity)
          raise ArgumentError, "Builtin already registered: #{builtin_name}" if @builtins.key?(builtin_name)

          @builtins[builtin_name] = Entry.new(name: builtin_name, arity: arity, handler: block)
        end

        # @param name [String, Symbol]
        # @param args [Array<Object>]
        # @return [Ruby::Rego::Value]
        def call(name, args)
          entry = fetch_entry(normalize_name(name))
          invoke_entry(entry, args)
        end

        # @param name [String, Symbol]
        # @return [Entry]
        def entry_for(name)
          fetch_entry(normalize_name(name))
        end

        # @param name [String, Symbol]
        # @param entry [Entry]
        # @yieldreturn [Object]
        # @return [Object]
        def with_entry_override(name, entry)
          builtin_name = normalize_name(name)
          previous = fetch_entry(builtin_name)
          @builtins[builtin_name] = entry
          yield
        ensure
          @builtins[builtin_name] = previous
        end

        # @param name [String, Symbol]
        # @param entry [Entry]
        # @return [BuiltinRegistryOverlay]
        def with_override(name, entry)
          BuiltinRegistryOverlay.new(
            base_registry: self,
            overrides: { normalize_name(name) => entry }
          )
        end

        # @param name [String, Symbol]
        # @return [Boolean]
        def registered?(name)
          @builtins.key?(normalize_name(name))
        end

        private

        # :reek:UtilityFunction
        # :reek:FeatureEnvy
        def validate_arity(arity)
          return if arity.is_a?(Integer) && arity >= 0

          raise ArgumentError, "Arity must be a non-negative Integer"
        end

        def fetch_entry(builtin_name)
          @builtins.fetch(builtin_name) do
            raise EvaluationError, "Undefined built-in function: #{builtin_name}"
          end
        end
      end

      # Registry wrapper that overlays builtin entries without mutating the base registry.
      class BuiltinRegistryOverlay
        include BuiltinInvocation

        # @param base_registry [BuiltinRegistry]
        # @param overrides [Hash{String => BuiltinRegistry::Entry}]
        def initialize(base_registry:, overrides: {})
          @base_registry = base_registry
          @overrides = overrides
        end

        # @param name [String, Symbol]
        # @param entry [BuiltinRegistry::Entry]
        # @return [BuiltinRegistryOverlay]
        def with_override(name, entry)
          normalized = normalize_name(name)
          self.class.new(base_registry: base_registry, overrides: overrides.merge(normalized => entry))
        end

        # @param name [String, Symbol]
        # @param args [Array<Object>]
        # @return [Ruby::Rego::Value]
        def call(name, args)
          entry = entry_for(name)
          invoke_entry(entry, args)
        end

        # @param name [String, Symbol]
        # @return [BuiltinRegistry::Entry]
        def entry_for(name)
          normalized = normalize_name(name)
          overrides.fetch(normalized) { base_registry.entry_for(normalized) }
        end

        # @param name [String, Symbol]
        # @return [Boolean]
        def registered?(name)
          normalized = normalize_name(name)
          overrides.key?(normalized) || base_registry.registered?(normalized)
        end

        private

        attr_reader :base_registry, :overrides
      end
    end
  end
end
