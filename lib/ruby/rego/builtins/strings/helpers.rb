# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        BASE_DIGITS = %w[
          0 1 2 3 4 5 6 7 8 9
          a b c d e f g h i j
          k l m n o p q r s t
          u v w x y z
        ].freeze

        def self.string_value(value, context:)
          Base.assert_type(value, expected: StringValue, context: context)
          value.value
        end
        private_class_method :string_value

        def self.array_values(value, name:)
          Base.assert_type(value, expected: ArrayValue, context: name)
          value.value
        end
        private_class_method :array_values

        def self.string_array(value, name:)
          string_elements(array_values(value, name: name), name: name)
        end
        private_class_method :string_array

        # Asserts each element is a string and returns the underlying Ruby strings.
        # Shared by string_array (arrays) and string_set (sets).
        def self.string_elements(elements, name:)
          elements.map.with_index do |element, index|
            Base.assert_type(element, expected: StringValue, context: "#{name} element #{index}")
            element.value
          end
        end
        private_class_method :string_elements

        # Coerces a string, array, or set argument into an Array of Ruby strings.
        # Non-string elements raise (yielding an undefined result), matching OPA's
        # `string | array[string] | set[string]` argument typing.
        def self.string_collection(value, name:)
          return [string_value(value, context: name)] if value.is_a?(StringValue)
          return string_array(value, name: name) if value.is_a?(ArrayValue)
          return string_set(value, name: name) if value.is_a?(SetValue)

          Base.assert_type(value, expected: [StringValue, ArrayValue, SetValue], context: name)
          []
        end
        private_class_method :string_collection

        def self.string_set(value, name:)
          string_elements(value.value, name: name)
        end
        private_class_method :string_set

        # Coerces an object argument into a Ruby Hash of string keys to string values.
        # Non-string keys or values raise (yielding an undefined result), matching OPA's
        # `object[string: string]` argument typing.
        #
        # :reek:TooManyStatements
        def self.string_hash(value, name:)
          Base.assert_type(value, expected: ObjectValue, context: name)
          result = {} # @type var result: Hash[String, String]
          value.value.each do |key, val|
            assert_string_key(key, name: name)
            Base.assert_type(val, expected: StringValue, context: "#{name} value")
            result[key] = val.value
          end
          result
        end
        private_class_method :string_hash

        def self.assert_string_key(key, name:)
          return if key.is_a?(String)

          raise Ruby::Rego::BuiltinArgumentError.new(
            "Type mismatch",
            expected: "String",
            actual: key.class.name,
            context: "#{name} key",
            location: nil
          )
        end
        private_class_method :assert_string_key

        # :reek:LongParameterList
        def self.string_pair(left, right, left_context:, right_context:)
          [
            string_value(left, context: left_context),
            string_value(right, context: right_context)
          ]
        end
        private_class_method :string_pair

        def self.sprintf_values(args)
          array_values(args, name: "sprintf args").map { |value| Base.to_ruby(value) }
        end
        private_class_method :sprintf_values

        def self.raise_sprintf_error(error)
          raise Ruby::Rego::BuiltinArgumentError.new(
            error.message,
            expected: "sprintf-compatible arguments",
            actual: error.class.name,
            context: "sprintf",
            location: nil
          )
        end
        private_class_method :raise_sprintf_error
      end
    end
  end
end
