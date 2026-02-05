# frozen_string_literal: true

# rubocop:disable Lint/RedundantRequireStatement
require "set"
# rubocop:enable Lint/RedundantRequireStatement
require_relative "errors"

module Ruby
  module Rego
    # Base class for Rego values.
    class Value
      TYPE_NAME = "value"

      # @param value [Object]
      def initialize(value = nil)
        @value = value
      end

      # @return [Object]
      attr_reader :value

      # @return [Boolean]
      def truthy?
        true
      end

      # @return [Object]
      def to_ruby
        value
      end

      # @return [String]
      def type_name
        self.class::TYPE_NAME
      end

      # @param other [Object]
      # @return [Boolean]
      def ==(other)
        other.is_a?(self.class) && other.to_ruby == to_ruby
      end

      alias eql? ==

      # @return [Integer]
      def hash
        [self.class.name, to_ruby].hash
      end

      # @param value [Object]
      # @return [Value]
      def self.from_ruby(value)
        return value if value.is_a?(Value)
        return UndefinedValue.new if value.equal?(UndefinedValue::UNDEFINED)

        built_value = build_value(value)
        return built_value if built_value

        raise ArgumentError, "Unsupported value type: #{value.class}"
      end

      def self.build_value(value)
        build_simple_value(value) || build_composite_value(value)
      end
      private_class_method :build_value

      def self.build_simple_value(value)
        case value
        when NilClass
          NullValue.new
        when TrueClass, FalseClass
          BooleanValue.new(value)
        when String
          StringValue.new(value)
        when Numeric
          NumberValue.new(value)
        end
      end
      private_class_method :build_simple_value

      def self.build_composite_value(value)
        case value
        when Array
          ArrayValue.new(value)
        when Hash
          ObjectValue.new(value)
        when Set
          SetValue.new(value)
        end
      end
      private_class_method :build_composite_value
    end

    # Represents a string value.
    class StringValue < Value
      TYPE_NAME = "string"

      # @param value [String]
      def initialize(value)
        super(String(value))
      end
    end

    # Represents a numeric value.
    class NumberValue < Value
      TYPE_NAME = "number"

      # @param value [Numeric]
      def initialize(value)
        raise ArgumentError, "Expected Numeric, got #{value.class}" unless value.is_a?(Numeric)

        super
      end
    end

    # Represents a boolean value.
    class BooleanValue < Value
      TYPE_NAME = "boolean"

      # @param value [Boolean]
      def initialize(value)
        klass = value.class
        raise ArgumentError, "Expected Boolean, got #{klass}" unless [TrueClass, FalseClass].include?(klass)

        super
      end

      # @return [Boolean]
      def truthy?
        value
      end
    end

    # Represents a null value.
    class NullValue < Value
      TYPE_NAME = "null"

      def initialize
        super(nil)
      end

      # @return [Boolean]
      def truthy?
        false
      end
    end

    # Represents an undefined value.
    class UndefinedValue < Value
      TYPE_NAME = "undefined"
      UNDEFINED = Object.new.freeze

      def initialize
        super(UNDEFINED)
      end

      # @return [Boolean]
      def truthy?
        false
      end

      # @return [Object]
      def to_ruby
        UNDEFINED
      end
    end

    # Represents an array value.
    class ArrayValue < Value
      TYPE_NAME = "array"

      # @param elements [Array<Object>]
      def initialize(elements)
        @elements = elements.map { |element| Value.from_ruby(element) }
        super(@elements)
      end

      # @param index [Integer]
      # @return [Value]
      def fetch_index(index)
        return UndefinedValue.new unless index.is_a?(Integer)

        @elements[index] || UndefinedValue.new
      end

      # @return [Array<Object>]
      def to_ruby
        @elements.map(&:to_ruby)
      end

      private

      attr_reader :elements
    end

    # Represents an object value.
    class ObjectValue < Value
      TYPE_NAME = "object"

      # @param pairs [Hash<Object, Object>]
      def initialize(pairs)
        @values = normalize_pairs(pairs)
        super(@values)
      end

      # :reek:TooManyStatements
      # :reek:FeatureEnvy
      def normalize_pairs(pairs)
        values = {} # @type var values: Hash[Object, Value]
        key_sources = {} # @type var key_sources: Hash[Object, Object]
        pairs.each_with_object(values) do |(key, val), acc|
          normalized_key = key.is_a?(Symbol) ? key.to_s : key
          ensure_unique_key(normalized_key, key_sources, key)
          acc[normalized_key] = Value.from_ruby(val)
        end
        values
      end

      # :reek:FeatureEnvy
      def ensure_unique_key(normalized_key, key_sources, key)
        return unless key_sources.key?(normalized_key)

        existing_key = key_sources[normalized_key]
        raise Error, "Conflicting object keys: #{existing_key.inspect} and #{key.inspect}"
      ensure
        key_sources[normalized_key] = key
      end

      # @param key [Object]
      # @return [Value]
      def fetch(key)
        return @values[key] if @values.key?(key)

        return fetch_by_symbol_key(key) if key.is_a?(Symbol)

        UndefinedValue.new
      end

      def fetch_by_symbol_key(key)
        string_key = key.to_s
        @values[string_key] || UndefinedValue.new
      end

      # @return [Hash<Object, Object>]
      def to_ruby
        @values.transform_values(&:to_ruby)
      end

      private

      attr_reader :values
      private :fetch_by_symbol_key, :normalize_pairs, :ensure_unique_key
    end

    # Represents a set value.
    class SetValue < Value
      TYPE_NAME = "set"

      # @param elements [Set<Object>, Array<Object>]
      def initialize(elements)
        collection = elements.is_a?(Set) ? elements.to_a : Array(elements)
        @elements = Set.new(collection.map { |element| Value.from_ruby(element) })
        super(@elements)
      end

      # @param value [Object]
      # @return [Boolean]
      def include?(value)
        @elements.include?(Value.from_ruby(value))
      end

      # @return [Set<Object>]
      def to_ruby
        Set.new(@elements.map(&:to_ruby))
      end

      private

      attr_reader :elements
    end
  end
end
