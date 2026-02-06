# frozen_string_literal: true

require_relative "../errors"
require_relative "../value"

module Ruby
  module Rego
    module Builtins
      # Shared helpers for built-in function implementations.
      module Base
        # @param args [Array<Object>]
        # @param expected [Integer]
        # @param name [String, nil]
        # @return [void]
        def self.assert_arity(args, expected, name: nil)
          actual = args.size
          return if actual == expected

          context = name ? "builtin #{name}" : nil
          raise Ruby::Rego::TypeError.new(
            "Wrong number of arguments",
            expected: expected,
            actual: actual,
            context: context,
            location: nil
          )
        end

        # @param value [Object]
        # @param expected [Class, Array<Class>]
        # @param context [String, nil]
        # @return [void]
        def self.assert_type(value, expected:, context: nil)
          expected_classes = normalize_expected(expected)
          return if expected_classes.any? { |klass| value.is_a?(klass) }

          raise_type_error(
            expected: expected_classes.map(&:name).join(" or "),
            actual: value.class.name,
            context: context
          )
        end

        # @param value [Object]
        # @return [Object]
        def self.to_ruby(value)
          value.is_a?(Ruby::Rego::Value) ? value.to_ruby : value
        end

        # @param value [Object]
        # @return [Ruby::Rego::Value]
        def self.to_value(value)
          Ruby::Rego::Value.from_ruby(value)
        end

        def self.normalize_expected(expected)
          expected.is_a?(Array) ? expected : [expected]
        end
        private_class_method :normalize_expected

        def self.raise_type_error(expected:, actual:, context: nil)
          raise Ruby::Rego::TypeError.new(
            "Type mismatch",
            expected: expected,
            actual: actual,
            context: context,
            location: nil
          )
        end
        private_class_method :raise_type_error
      end
    end
  end
end
