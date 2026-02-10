# frozen_string_literal: true

require_relative "../errors"
require_relative "../value"

module Ruby
  module Rego
    module Builtins
      # Shared helpers for built-in function implementations.
      module Base
        # @param args [Array<Object>]
        # @param expected [Integer, Array<Integer>]
        # @param name [String, nil]
        # @return [void]
        def self.assert_arity(args, expected, name: nil)
          actual = args.size
          return if arity_valid?(actual, expected)

          raise_builtin_arity_error(actual, expected, name)
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

        def self.normalize_arity(expected)
          expected.is_a?(Array) ? expected : [expected]
        end
        private_class_method :normalize_arity

        def self.format_arity(expected_list)
          expected_list.map(&:to_i).uniq.sort.join(" or ")
        end
        private_class_method :format_arity

        def self.arity_valid?(actual, expected)
          normalize_arity(expected).include?(actual)
        end
        private_class_method :arity_valid?

        def self.raise_builtin_arity_error(actual, expected, name)
          context = name ? "builtin #{name}" : nil
          expected_list = normalize_arity(expected)
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Wrong number of arguments",
            expected: format_arity(expected_list),
            actual: actual,
            context: context,
            location: nil
          )
        end
        private_class_method :raise_builtin_arity_error

        def self.raise_type_error(expected:, actual:, context: nil)
          raise Ruby::Rego::BuiltinArgumentError.new(
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
