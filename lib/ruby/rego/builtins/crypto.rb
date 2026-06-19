# frozen_string_literal: true

require "digest"
require "openssl"
require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

module Ruby
  module Rego
    module Builtins
      # Built-in cryptographic helpers: plain digests (crypto.md5/sha1/sha256) and keyed
      # HMAC digests (crypto.hmac.md5/sha1/sha256/sha512) plus a constant-time HMAC
      # comparison (crypto.hmac.equal). Digests are computed over the bytes of the input
      # string(s). Values from JSON/Rego input are UTF-8, so this matches OPA; a
      # caller-supplied non-UTF-8 Ruby String (outside the documented input contract) is
      # hashed as its own bytes. The HMAC argument order is OPA's (message, key) — the
      # reverse of Ruby's OpenSSL::HMAC.hexdigest(digest, key, message).
      module Crypto
        extend RegistryHelpers

        # Maps each crypto.hmac.* digest builtin to its OpenSSL digest name.
        HMAC_ALGORITHMS = {
          "crypto.hmac.md5" => "MD5",
          "crypto.hmac.sha1" => "SHA1",
          "crypto.hmac.sha256" => "SHA256",
          "crypto.hmac.sha512" => "SHA512"
        }.freeze

        CRYPTO_FUNCTIONS = {
          "crypto.md5" => { arity: 1, handler: :md5 },
          "crypto.sha1" => { arity: 1, handler: :sha1 },
          "crypto.sha256" => { arity: 1, handler: :sha256 },
          "crypto.hmac.md5" => { arity: 2, handler: :hmac_md5 },
          "crypto.hmac.sha1" => { arity: 2, handler: :hmac_sha1 },
          "crypto.hmac.sha256" => { arity: 2, handler: :hmac_sha256 },
          "crypto.hmac.sha512" => { arity: 2, handler: :hmac_sha512 },
          "crypto.hmac.equal" => { arity: 2, handler: :hmac_equal },
          "crypto.x509.parse_rsa_private_key" => { arity: 1, handler: :parse_rsa_private_key },
          "crypto.parse_private_keys" => { arity: 1, handler: :parse_private_keys }
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

        # @param message_value [Ruby::Rego::Value]
        # @param key_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.hmac_md5(message_value, key_value)
          hmac(message_value, key_value, "crypto.hmac.md5")
        end

        # @param message_value [Ruby::Rego::Value]
        # @param key_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.hmac_sha1(message_value, key_value)
          hmac(message_value, key_value, "crypto.hmac.sha1")
        end

        # @param message_value [Ruby::Rego::Value]
        # @param key_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.hmac_sha256(message_value, key_value)
          hmac(message_value, key_value, "crypto.hmac.sha256")
        end

        # @param message_value [Ruby::Rego::Value]
        # @param key_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.hmac_sha512(message_value, key_value)
          hmac(message_value, key_value, "crypto.hmac.sha512")
        end

        # Computes the hex HMAC of (message, key) using the digest configured for `context`.
        # OPA's argument order is (message, key); OpenSSL::HMAC.hexdigest takes (digest, key,
        # message), so the operands are passed in that order.
        #
        # @param message_value [Ruby::Rego::Value]
        # @param key_value [Ruby::Rego::Value]
        # @param context [String]
        # @return [Ruby::Rego::StringValue]
        def self.hmac(message_value, key_value, context)
          message = string_value(message_value, context)
          key = string_value(key_value, context)
          StringValue.new(OpenSSL::HMAC.hexdigest(HMAC_ALGORITHMS.fetch(context), key, message))
        end
        private_class_method :hmac

        # Constant-time comparison of two MAC strings (OPA's crypto.hmac.equal). Uses
        # OpenSSL.secure_compare, which is timing-safe and returns false (rather than
        # raising) for unequal-length inputs, matching Go's hmac.Equal.
        #
        # @param mac1_value [Ruby::Rego::Value]
        # @param mac2_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.hmac_equal(mac1_value, mac2_value)
          left = string_value(mac1_value, "crypto.hmac.equal")
          right = string_value(mac2_value, "crypto.hmac.equal")
          BooleanValue.new(OpenSSL.secure_compare(left, right))
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

require_relative "crypto/keys"
require_relative "crypto/certificates"
require_relative "crypto/certificate_request"

Ruby::Rego::Builtins::Crypto.register!
