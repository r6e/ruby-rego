# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        # @param haystack [Ruby::Rego::Value]
        # @param needle [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.contains(haystack, needle)
          haystack_text = string_value(haystack, context: "contains haystack")
          needle_text = string_value(needle, context: "contains needle")
          BooleanValue.new(haystack_text.include?(needle_text))
        end

        # @param string [Ruby::Rego::Value]
        # @param prefix [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.startswith(string, prefix)
          string_text = string_value(string, context: "startswith string")
          prefix_text = string_value(prefix, context: "startswith prefix")
          BooleanValue.new(string_text.start_with?(prefix_text))
        end

        # @param string [Ruby::Rego::Value]
        # @param suffix [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.endswith(string, suffix)
          string_text = string_value(string, context: "endswith string")
          suffix_text = string_value(suffix, context: "endswith suffix")
          BooleanValue.new(string_text.end_with?(suffix_text))
        end

        # @param haystack [Ruby::Rego::Value]
        # @param needle [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.indexof(haystack, needle)
          haystack_text = string_value(haystack, context: "indexof haystack")
          needle_text = string_value(needle, context: "indexof needle")
          index = haystack_text.index(needle_text)
          NumberValue.new(index || -1)
        end
      end
    end
  end
end
