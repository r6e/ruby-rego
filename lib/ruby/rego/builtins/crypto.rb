# frozen_string_literal: true

require "digest"
require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

module Ruby
  module Rego
    module Builtins
      # Built-in cryptographic hashing helpers (crypto.md5, crypto.sha1, crypto.sha256).
      # Digests are computed over the bytes of the input string. Values from JSON/Rego
      # input are UTF-8, so this matches OPA; a caller-supplied non-UTF-8 Ruby String
      # (outside the documented input contract) is hashed as its own bytes.
      module Crypto
        extend RegistryHelpers

        CRYPTO_FUNCTIONS = {
          "crypto.md5" => { arity: 1, handler: :md5 },
          "crypto.sha1" => { arity: 1, handler: :sha1 },
          "crypto.sha256" => { arity: 1, handler: :sha256 }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, CRYPTO_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.md5(value)
          StringValue.new(Digest::MD5.hexdigest(string_value(value, "crypto.md5")))
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.sha1(value)
          StringValue.new(Digest::SHA1.hexdigest(string_value(value, "crypto.sha1")))
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.sha256(value)
          StringValue.new(Digest::SHA256.hexdigest(string_value(value, "crypto.sha256")))
        end

        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [String]
        def self.string_value(value, context)
          Base.assert_type(value, expected: StringValue, context: context)
          value.value
        end
        private_class_method :string_value
      end
    end
  end
end

Ruby::Rego::Builtins::Crypto.register!
