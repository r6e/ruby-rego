# frozen_string_literal: true

module Ruby
  module Rego
    # Immutable set of compiled modules keyed by package path.
    class CompiledPolicySet
      # @param modules [Array<CompiledModule>] compiled modules
      def initialize(modules)
        @modules_by_key = index_by_package_key(modules).freeze
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
        matches = package_keys.select { |package_key| prefix_match?(package_key, string_keys) }
        matches.max_by { |package_key| package_key.split(".").length }
      end

      # @param package_key [String] candidate package key
      # @param string_keys [Array<String>] reference key list as strings
      # @return [Boolean]
      def self.prefix_match?(package_key, string_keys)
        segments = package_key.split(".")
        length = segments.length
        string_keys.length > length && string_keys[0, length] == segments
      end
      private_class_method :prefix_match?

      private

      attr_reader :modules_by_key

      # @param modules [Array<CompiledModule>] compiled modules
      # @return [Hash{String => CompiledModule}]
      def index_by_package_key(modules)
        by_key = {} # @type var by_key: Hash[String, CompiledModule]
        modules.each do |mod|
          key = mod.package_path.join(".")
          raise ArgumentError, "Duplicate package key: #{key}" if by_key.key?(key)

          by_key[key] = mod
        end
        by_key
      end
    end
  end
end
