# frozen_string_literal: true

require_relative "../compiled_policy_set"

module Ruby
  module Rego
    class Evaluator
      # Maps package keys to reference resolvers for cross-package dispatch.
      class ModuleContextRegistry
        # @param resolvers_by_key [Hash{String => ReferenceResolver}]
        def initialize(resolvers_by_key)
          @resolvers_by_key = resolvers_by_key
          @package_keys = resolvers_by_key.keys
        end

        # Find the resolver whose package is the longest prefix of keys.
        #
        # @param keys [Array<Object>] reference key list
        # @return [ReferenceResolver, nil]
        def resolver_for(keys)
          key = CompiledPolicySet.longest_prefix_key(package_keys, keys)
          key && resolvers_by_key[key]
        end

        private

        attr_reader :resolvers_by_key, :package_keys
      end
    end
  end
end
