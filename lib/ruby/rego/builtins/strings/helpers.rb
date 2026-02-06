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
          array_values(value, name: name).map.with_index do |element, index|
            Base.assert_type(element, expected: StringValue, context: "#{name} element #{index}")
            element.value
          end
        end
        private_class_method :string_array

        def self.sprintf_values(args)
          array_values(args, name: "sprintf args").map { |value| Base.to_ruby(value) }
        end
        private_class_method :sprintf_values

        def self.raise_sprintf_error(error)
          raise Ruby::Rego::TypeError.new(
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
