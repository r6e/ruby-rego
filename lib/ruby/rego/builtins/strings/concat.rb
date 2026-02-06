# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        # @param delimiter [Ruby::Rego::Value]
        # @param array [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.concat(delimiter, array)
          delimiter_string = string_value(delimiter, context: "concat delimiter")
          parts = string_array(array, name: "concat")
          StringValue.new(parts.join(delimiter_string))
        end
      end
    end
  end
end
