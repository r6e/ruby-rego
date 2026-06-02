# frozen_string_literal: true

module Ruby
  module Rego
    # Immutable set of compiled modules keyed by package path.
    class CompiledPolicySet
      # @param modules [Array<CompiledModule>] compiled modules
      def initialize(modules)
        by_key = {} # @type var by_key: Hash[String, CompiledModule]
        modules.each { |mod| by_key[mod.package_path.join(".")] = mod }
        @modules_by_key = by_key.freeze
      end

      # @return [Array<CompiledModule>]
      def modules
        modules_by_key.values
      end

      # @return [Array<String>]
      def package_keys
        modules_by_key.keys
      end

      # Find the module whose package path is the longest prefix of keys.
      #
      # @param keys [Array<Object>] reference key list
      # @return [CompiledModule, nil]
      def module_for(keys)
        key = self.class.longest_prefix_key(package_keys, keys)
        key && modules_by_key[key]
      end

      # Find the package key whose path is the longest prefix of keys.
      #
      # @param package_keys [Array<String>] candidate package keys
      # @param keys [Array<Object>] reference key list
      # @return [String, nil]
      def self.longest_prefix_key(package_keys, keys)
        string_keys = keys.map(&:to_s)
        best = nil # @type var best: String?
        package_keys.each do |package_key|
          segments = package_key.split(".")
          length = segments.length
          next unless string_keys.length > length && string_keys[0, length] == segments
          next if best && best.split(".").length >= length

          best = package_key
        end
        best
      end

      private

      attr_reader :modules_by_key
    end
  end
end
