# frozen_string_literal: true

# rubocop:disable Lint/RedundantRequireStatement
require "set"
# rubocop:enable Lint/RedundantRequireStatement
require_relative "errors"

module Ruby
  module Rego
    # Base class for Rego values.
    # :reek:InstanceVariableAssumption (lazily memoizes @canonical)
    class Value
      TYPE_NAME = "value"

      # Create a value wrapper.
      #
      # @param value [Object] underlying value
      def initialize(value = nil)
        @value = value
      end

      # The wrapped Ruby value.
      #
      # @return [Object]
      attr_reader :value

      # Determine truthiness for Rego evaluation.
      #
      # @return [Boolean]
      def truthy?
        true
      end

      # Convert the value back to Ruby.
      #
      # @return [Object]
      def to_ruby
        value
      end

      # Return the Rego type name.
      #
      # @return [String]
      def type_name
        self.class::TYPE_NAME
      end

      # Resolve a reference on the value.
      #
      # @param _key [Object] reference key
      # @return [Value] resolved value or undefined
      def fetch_reference(_key)
        return self if undefined?

        UndefinedValue.new
      end

      # Check if the value is undefined.
      #
      # @return [Boolean]
      def undefined?
        is_a?(UndefinedValue)
      end

      # Return a normalized object key representation.
      #
      # @return [Object]
      def object_key
        to_ruby
      end

      # Compare values by class and canonical Ruby value. The canonical form makes
      # numerically-equal numbers (e.g. 1 and 1.0) compare equal everywhere — including as
      # array/set/object members — matching OPA, where 1 == 1.0.
      #
      # @param other [Object]
      # @return [Boolean]
      def ==(other)
        other.is_a?(self.class) && other.canonical == canonical
      end

      alias eql? ==

      # Hash for use in Ruby collections, consistent with ==/eql? (so a Set/Hash dedups 1 and
      # 1.0). Without this, eql?-equal numbers could hash differently and never collapse.
      #
      # @return [Integer]
      def hash
        [self.class.name, canonical].hash
      end

      # The value's canonical Ruby form: numerically-equal numbers are unified (an
      # integer-valued Float collapses to its Integer) recursively through arrays, sets, and
      # objects, so identity/equality/hashing match OPA's number semantics. `to_ruby` still
      # returns the original (first-seen) representation.
      #
      # @return [Object]
      def canonical
        return @canonical if defined?(@canonical)

        @canonical = self.class.canonicalize(to_ruby)
      end

      # @param value [Object] a Ruby value (as produced by #to_ruby)
      # @return [Object]
      def self.canonicalize(value)
        case value
        when ::Float then canonicalize_float(value)
        when ::Array then canonicalize_each(value)
        when ::Set then ::Set.new(canonicalize_each(value))
        when ::Hash then value.to_h { |key, val| [canonicalize(key), canonicalize(val)] }
        else value
        end
      end

      # @return [Array]
      def self.canonicalize_each(collection)
        collection.map { |element| canonicalize(element) }
      end

      # An integer-valued Float collapses to its Integer so it compares and hashes like the
      # integer; any other (fractional, infinite, NaN) Float is left as-is.
      # @return [Numeric]
      def self.canonicalize_float(value)
        return value unless value.finite?

        integer = value.to_i
        value == integer ? integer : value
      end

      # Coerce Ruby values into Rego values.
      #
      # @param value [Object] value to convert
      # @return [Value] converted value
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

      # Create a string value.
      #
      # @param value [String] string value
      def initialize(value)
        super(String(value))
      end
    end

    # Represents a numeric value.
    class NumberValue < Value
      TYPE_NAME = "number"

      # Create a numeric value.
      #
      # @param value [Numeric] numeric value
      def initialize(value)
        raise ArgumentError, "Expected Numeric, got #{value.class}" unless value.is_a?(Numeric)

        super
      end
    end

    # Represents a boolean value.
    class BooleanValue < Value
      TYPE_NAME = "boolean"

      # Create a boolean value.
      #
      # @param value [Boolean] boolean value
      def initialize(value)
        klass = value.class
        raise ArgumentError, "Expected Boolean, got #{klass}" unless [TrueClass, FalseClass].include?(klass)

        super
      end

      # Determine truthiness.
      #
      # @return [Boolean]
      def truthy?
        value
      end
    end

    # Represents a null value.
    class NullValue < Value
      TYPE_NAME = "null"

      # Create a null value.
      def initialize
        super(nil)
      end

      # Null is falsy.
      #
      # @return [Boolean]
      def truthy?
        false
      end
    end

    # Represents an undefined value.
    class UndefinedValue < Value
      TYPE_NAME = "undefined"
      UNDEFINED = Object.new.freeze

      # Create an undefined value marker.
      def initialize
        super(UNDEFINED)
      end

      # Undefined is falsy.
      #
      # @return [Boolean]
      def truthy?
        false
      end

      # Return the singleton undefined marker.
      #
      # @return [Object]
      def to_ruby
        UNDEFINED
      end

      # Use the instance itself as an object key.
      #
      # @return [UndefinedValue]
      def object_key
        self
      end
    end

    # Represents an array value.
    class ArrayValue < Value
      TYPE_NAME = "array"

      # Create an array value.
      #
      # @param elements [Array<Object>] elements to wrap
      def initialize(elements)
        @elements = elements.map { |element| Value.from_ruby(element) }
        super(@elements)
      end

      # Fetch an element by index.
      #
      # @param index [Integer] array index
      # @return [Value] element or undefined
      def fetch_index(index)
        return UndefinedValue.new unless index.is_a?(Integer)

        @elements[index] || UndefinedValue.new
      end

      # Resolve a reference for an array.
      #
      # @param key [Object] index value
      # @return [Value] element or undefined
      def fetch_reference(key)
        fetch_index(key)
      end

      # Convert the array back to Ruby.
      #
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

      # Create an object value.
      #
      # @param pairs [Hash<Object, Object>] object pairs
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
        raise ObjectKeyConflictError, "Conflicting object keys: #{existing_key.inspect} and #{key.inspect}"
      ensure
        key_sources[normalized_key] = key
      end

      # Fetch a value by key.
      #
      # @param key [Object] object key
      # @return [Value] value or undefined
      def fetch(key)
        return @values[key] if @values.key?(key)

        return fetch_by_symbol_key(key) if key.is_a?(Symbol)

        UndefinedValue.new
      end

      # Resolve a reference for an object.
      #
      # @param key [Object] object key
      # @return [Value] value or undefined
      def fetch_reference(key)
        fetch(key)
      end

      def fetch_by_symbol_key(key)
        string_key = key.to_s
        @values[string_key] || UndefinedValue.new
      end

      # Convert the object back to Ruby.
      #
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

      # Create a set value.
      #
      # @param elements [Set<Object>, Array<Object>] set elements
      def initialize(elements)
        collection = elements.is_a?(Set) ? elements.to_a : Array(elements)
        @elements = Set.new(collection.map { |element| Value.from_ruby(element) })
        super(@elements)
      end

      # Check whether the set includes a value.
      #
      # @param value [Object] value to check
      # @return [Boolean]
      def include?(value)
        @elements.include?(Value.from_ruby(value))
      end

      # Convert the set back to Ruby.
      #
      # @return [Set<Object>]
      def to_ruby
        Set.new(@elements.map(&:to_ruby))
      end

      private

      attr_reader :elements
    end
  end
end
