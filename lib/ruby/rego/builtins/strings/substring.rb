# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        # @param string [Ruby::Rego::Value]
        # @param offset [Ruby::Rego::Value]
        # @param length [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.substring(string, offset, length)
          string_text = string_value(string, context: "substring string")
          offset_value = NumericHelpers.non_negative_integer(offset, context: "substring offset")
          length_value = NumericHelpers.non_negative_integer(length, context: "substring length")
          substring = string_text.slice(offset_value, length_value) || ""
          StringValue.new(substring)
        end
      end
    end
  end
end
