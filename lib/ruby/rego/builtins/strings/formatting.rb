# frozen_string_literal: true

# rubocop:disable Naming/RescuedExceptionsVariableName

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        # @param number [Ruby::Rego::Value]
        # @param base [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.format_int(number, base)
          number_value = NumericHelpers.integer_value(number, context: "format_int number")
          base_value = NumericHelpers.integer_value(base, context: "format_int base")
          ensure_base(base_value)
          StringValue.new(base_encode(number_value, base_value))
        end

        # @param format [Ruby::Rego::Value]
        # @param args [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.sprintf(format, args)
          format_value = string_value(format, context: "sprintf format")
          values = sprintf_values(args)
          StringValue.new(Kernel.sprintf(format_value, *values))
        rescue ArgumentError, ::TypeError => error
          raise_sprintf_error(error)
        end
      end
    end
  end
end

# rubocop:enable Naming/RescuedExceptionsVariableName
