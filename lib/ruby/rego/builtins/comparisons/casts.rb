# frozen_string_literal: true

require_relative "../base"
require_relative "../../errors"
require_relative "../../number"
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

          # Parse to_number's string argument (verified vs opa eval 1.17): the strict JSON-number grammar
          # with verbatim text preserved (1.50 -> 1.50, 1E5 -> 1E5, -0 -> -0), within float64 range. An
          # in-range value keeps its exact json.Number; anything else is undefined.
          #
          # OPA actually gates defined-ness on Go strconv.ParseFloat (lenient) while storing the original
          # text, so it ACCEPTS leading-zero / leading-+ / bare-dot / hex-float forms (007, .5, +5, 0x1p4)
          # in comparison/arithmetic yet crashes when marshaling them ("json: invalid number literal").
          # Preserving that verbatim text would reinstate the unmarshalable-Number serializer DoS #128
          # closed, so the gem deliberately accepts only the strict JSON grammar and routes those forms to
          # undefined. This is more-strict, not "safe" — see the spec for the locked contract.
          def self.number_from_string(text)
            return Number.build_number(text) if number_text_in_range?(text)

            raise_number_error(text)
          end
          private_class_method :number_from_string

          # Whether `text` is a `to_number`-acceptable number. The gates run in a DoS-safe order on
          # attacker-controlled input: (1) byte_safe_encoding? keeps the regex from RAISING on an
          # invalid-byte string (an uncaught error aborts the policy, not undefined); (2) the strict
          # grammar; (3) magnitude_within_limit? bounds rational materialization for an over-large or
          # over-tiny exponent BEFORE build_number realizes the value (the #128 serializer-DoS class —
          # float64_overflow? alone misses an underflow like 1e-1000000000, which is finite yet would
          # allocate a ~10**1e9 denominator); (4) float64_overflow? matches OPA's strconv.ParseFloat
          # ceiling so 1e309 / a >308-magnitude integer go undefined as in OPA.
          def self.number_text_in_range?(text)
            Base.byte_safe_encoding?(text) &&
              text.match?(Number::DECIMAL_STRING) &&
              Number.magnitude_within_limit?(text) &&
              !float64_overflow?(text)
          end
          private_class_method :number_text_in_range?

          # Whether `text` (already a valid JSON number) is too large for float64, i.e. parses to ±Infinity.
          # An underflow to 0 (e.g. 1e-400) is finite and accepted, matching OPA.
          def self.float64_overflow?(text)
            Float(text, exception: false)&.infinite? ? true : false
          end
          private_class_method :float64_overflow?

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
