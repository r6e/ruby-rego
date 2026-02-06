# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        # @param string [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.lower(string)
          StringValue.new(string_value(string, context: "lower").downcase)
        end

        # @param string [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.upper(string)
          StringValue.new(string_value(string, context: "upper").upcase)
        end
      end
    end
  end
end
