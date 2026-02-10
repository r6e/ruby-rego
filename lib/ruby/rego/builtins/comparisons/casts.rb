# frozen_string_literal: true

require_relative "../base"
require_relative "../../errors"
require_relative "../../value"

module Ruby
  module Rego
    module Builtins
      module Comparisons
        # Casting and conversion helpers.
        module Casts
          # @param value [Ruby::Rego::Value]
          # @return [Ruby::Rego::NumberValue]
          def self.to_number(value)
            raw = value.value
            return NumberValue.new(raw) if value.is_a?(NumberValue)
            return NumberValue.new(number_from_string(raw)) if value.is_a?(StringValue)

            raise_type_mismatch("to_number", "number or string", value.class.name)
          end

          # @param value [Ruby::Rego::Value]
          # @return [Ruby::Rego::StringValue]
          def self.cast_string(value)
            Base.assert_type(
              value,
              expected: [StringValue, NumberValue, BooleanValue, NullValue],
              context: "cast_string"
            )

            return value if value.is_a?(StringValue)
            return StringValue.new("null") if value.is_a?(NullValue)

            StringValue.new(Base.to_ruby(value).to_s)
          end

          # @param value [Ruby::Rego::Value]
          # @return [Ruby::Rego::BooleanValue]
          def self.cast_boolean(value)
            return value if value.is_a?(BooleanValue)

            raw = value.value
            return boolean_from_string(raw) if value.is_a?(StringValue)
            return boolean_from_number(raw) if value.is_a?(NumberValue)

            raise_type_mismatch("cast_boolean", "boolean, string, or number", value.class.name)
          end

          # @param value [Ruby::Rego::Value]
          # @return [Ruby::Rego::ArrayValue]
          def self.cast_array(value)
            return value if value.is_a?(ArrayValue)

            Base.assert_type(value, expected: [ArrayValue, SetValue], context: "cast_array")
            ArrayValue.new(value.value.to_a)
          end

          # @param value [Ruby::Rego::Value]
          # @return [Ruby::Rego::SetValue]
          def self.cast_set(value)
            return value if value.is_a?(SetValue)

            Base.assert_type(value, expected: [SetValue, ArrayValue], context: "cast_set")
            SetValue.new(value.value)
          end

          # @param value [Ruby::Rego::Value]
          # @return [Ruby::Rego::ObjectValue]
          def self.cast_object(value)
            object = value # @type var object: ObjectValue
            Base.assert_type(object, expected: ObjectValue, context: "cast_object")
            object
          end

          def self.number_from_string(text)
            Integer(text, 10)
          rescue ArgumentError
            float = Float(text, exception: false)
            return float if float&.finite?

            raise_number_error(text)
          end
          private_class_method :number_from_string

          def self.raise_number_error(text)
            raise Ruby::Rego::BuiltinArgumentError.new(
              "Invalid number string",
              expected: "numeric string",
              actual: text,
              context: "to_number",
              location: nil
            )
          end
          private_class_method :raise_number_error

          def self.boolean_from_string(text)
            normalized = text.strip.downcase
            return BooleanValue.new(true) if normalized == "true"
            return BooleanValue.new(false) if normalized == "false"

            raise_cast_error("Expected boolean string", "cast_boolean", text)
          end
          private_class_method :boolean_from_string

          def self.boolean_from_number(number)
            return BooleanValue.new(false) if number.zero?
            return BooleanValue.new(true) if number == 1

            raise_cast_error("Expected 0 or 1 for boolean cast", "cast_boolean", number)
          end
          private_class_method :boolean_from_number

          def self.raise_cast_error(message, context, actual)
            raise Ruby::Rego::BuiltinArgumentError.new(
              message,
              expected: "castable value",
              actual: actual,
              context: context,
              location: nil
            )
          end
          private_class_method :raise_cast_error

          def self.raise_type_mismatch(context, expected, actual)
            raise Ruby::Rego::BuiltinArgumentError.new(
              "Type mismatch",
              expected: expected,
              actual: actual,
              context: context,
              location: nil
            )
          end
          private_class_method :raise_type_mismatch
        end
      end
    end
  end
end
