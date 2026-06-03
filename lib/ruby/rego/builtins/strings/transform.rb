# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        # Replaces every non-overlapping literal occurrence of `old` with `new`
        # (matching OPA's `replace`; the search is literal, not a regex).
        #
        # @param string [Ruby::Rego::Value]
        # @param old [Ruby::Rego::Value]
        # @param replacement [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.replace(string, old, replacement)
          text = string_value(string, context: "replace string")
          old_text = string_value(old, context: "replace substring")
          new_text = string_value(replacement, context: "replace value")
          StringValue.new(text.gsub(old_text) { new_text })
        end

        # Reverses by Unicode codepoint (not grapheme cluster), matching OPA.
        #
        # @param string [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.strings_reverse(string)
          StringValue.new(string_value(string, context: "strings.reverse").reverse)
        end
      end
    end
  end
end
