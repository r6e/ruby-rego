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
          haystack_text, needle_text = string_pair(
            haystack,
            needle,
            left_context: "contains haystack",
            right_context: "contains needle"
          )
          BooleanValue.new(haystack_text.include?(needle_text))
        end

        # @param string [Ruby::Rego::Value]
        # @param prefix [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.startswith(string, prefix)
          string_text, prefix_text = string_pair(
            string,
            prefix,
            left_context: "startswith string",
            right_context: "startswith prefix"
          )
          BooleanValue.new(string_text.start_with?(prefix_text))
        end

        # @param string [Ruby::Rego::Value]
        # @param suffix [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.endswith(string, suffix)
          string_text, suffix_text = string_pair(
            string,
            suffix,
            left_context: "endswith string",
            right_context: "endswith suffix"
          )
          BooleanValue.new(string_text.end_with?(suffix_text))
        end

        # @param haystack [Ruby::Rego::Value]
        # @param needle [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.indexof(haystack, needle)
          haystack_text, needle_text = string_pair(
            haystack,
            needle,
            left_context: "indexof haystack",
            right_context: "indexof needle"
          )
          index = haystack_text.index(needle_text)
          NumberValue.new(index || -1)
        end

        # Counts non-overlapping occurrences of `search` in `string` (OPA's
        # strings.count). An empty search counts as the codepoint count plus one.
        #
        # @param string [Ruby::Rego::Value]
        # @param search [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.strings_count(string, search)
          haystack, needle = string_pair(
            string, search, left_context: "strings.count string", right_context: "strings.count search"
          )
          NumberValue.new(haystack.scan(needle).size)
        end

        # All start indices (by character) of `search` in `string`, including
        # overlapping matches (matching OPA: indexof_n("aaa","aa") => [0,1]).
        # An empty search yields an undefined result (matching OPA).
        #
        # @param string [Ruby::Rego::Value]
        # @param search [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        def self.indexof_n(string, search)
          haystack, needle = string_pair(
            string, search, left_context: "indexof_n string", right_context: "indexof_n search"
          )
          raise_empty_search("indexof_n") if needle.empty?
          ArrayValue.new(match_indices(haystack, needle).map { |index| NumberValue.new(index) })
        end

        def self.match_indices(haystack, needle)
          indices = [] # @type var indices: Array[Integer]
          position = 0
          while (found = haystack.index(needle, position))
            indices << found
            position = found + 1
          end
          indices
        end
        private_class_method :match_indices

        def self.raise_empty_search(context)
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Empty search string", expected: "non-empty search string", actual: "", context: context, location: nil
          )
        end
        private_class_method :raise_empty_search
      end
    end
  end
end
