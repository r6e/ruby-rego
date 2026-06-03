# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        # True if any string in `search` starts with any string in `base`, matching OPA's
        # `strings.any_prefix_match`. Each argument may be a string, array, or set of
        # strings; an empty collection yields false, and an empty base string is a prefix
        # of everything.
        #
        # @param search [Ruby::Rego::Value]
        # @param base [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.any_prefix_match(search, base)
          searches = string_collection(search, name: "strings.any_prefix_match search")
          bases = string_collection(base, name: "strings.any_prefix_match base")
          BooleanValue.new(any_pair_match?(searches, bases) { |candidate, affix| candidate.start_with?(affix) })
        end

        # True if any string in `search` ends with any string in `base`, matching OPA's
        # `strings.any_suffix_match`. Argument typing mirrors `any_prefix_match`.
        #
        # @param search [Ruby::Rego::Value]
        # @param base [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.any_suffix_match(search, base)
          searches = string_collection(search, name: "strings.any_suffix_match search")
          bases = string_collection(base, name: "strings.any_suffix_match base")
          BooleanValue.new(any_pair_match?(searches, bases) { |candidate, affix| candidate.end_with?(affix) })
        end

        def self.any_pair_match?(searches, bases, &predicate)
          searches.product(bases).any? { |candidate, affix| predicate.call(candidate, affix) }
        end
        private_class_method :any_pair_match?
      end
    end
  end
end
