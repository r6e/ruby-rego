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

        # Replaces occurrences of each key in `patterns` with its value, matching OPA's
        # `strings.replace_n` (a faithful port of Go's `strings.Replacer`): keys are
        # applied in ascending sort order with a single left-to-right pass, replaced text
        # is never rescanned, and on overlapping matches the earliest-sorted key wins.
        #
        # @param patterns [Ruby::Rego::Value] object of string keys to string replacements
        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.replace_n(patterns, value)
          mapping = string_hash(patterns, name: "strings.replace_n patterns")
          text = string_value(value, context: "strings.replace_n value")
          StringValue.new(apply_replace_n(text, mapping))
        end

        # Single-pass replacer mirroring Go's strings.Replacer Replace loop: gaps are
        # flushed lazily via `last`, and `prev_empty` prevents an empty-key match from
        # looping at the same position.
        #
        # :reek:TooManyStatements
        # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
        def self.apply_replace_n(text, mapping)
          keys = mapping.keys.sort
          out = +""
          last = 0
          index = 0
          prev_empty = false
          length = text.length
          while index <= length
            # Earliest-sorted key that prefixes the remainder wins (Go's highest priority);
            # the empty key is skipped right after a zero-width match to avoid looping.
            match = keys.find { |key| !(key.empty? && prev_empty) && text[index, key.length] == key }
            prev_empty = match ? match.empty? : false
            if match
              out << text[last...index].to_s << mapping.fetch(match)
              index += match.length
              last = index
            else
              index += 1
            end
          end
          out << text[last..].to_s
        end
        # rubocop:enable Metrics/AbcSize, Metrics/MethodLength
        private_class_method :apply_replace_n
      end
    end
  end
end
