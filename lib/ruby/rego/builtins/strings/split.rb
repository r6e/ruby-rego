# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        # @param string [Ruby::Rego::Value]
        # @param delimiter [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        def self.split(string, delimiter)
          string_text = string_value(string, context: "split string")
          delimiter_text = string_value(delimiter, context: "split delimiter")
          ArrayValue.new(string_text.split(delimiter_text, -1))
        end
      end
    end
  end
end
