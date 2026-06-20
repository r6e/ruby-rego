# frozen_string_literal: true

require "json"
require "openssl"
require_relative "../base64url"

module Ruby
  module Rego
    module Builtins
      module Jwt
        # Parses a JWK or JWK Set (RFC 7517) into OpenSSL public keys for io.jwt.verify_*. OPA's
        # getKeyFromCertOrJWK accepts a single JWK object or a `{"keys":[...]}` set and errors if any key
        # is unbuildable, so `keys` returns the built keys, or nil when the string is not a JWK shape or
        # ANY of its keys cannot be built (-> undefined), or [] for an empty `{"keys":[]}` set (the caller
        # verifies that as false). A private JWK (a `d` member) is rejected like OPA's public-key path.
        module Jwk
          # JWK `crv` -> OpenSSL curve name for EC keys.
          EC_CURVES = { "P-256" => "prime256v1", "P-384" => "secp384r1", "P-521" => "secp521r1" }.freeze

          # The OpenSSL public keys for a JWK or JWK Set, or nil when the string is not a JWK shape or any
          # of its keys cannot be built — OPA errors (undefined) if a key carries private material, has a
          # missing/garbled component or unknown kty, or if ANY key in a set is unbuildable. An empty
          # `{"keys":[]}` set yields [] (no key to try, which the caller verifies as false).
          # @param json_string [String]
          # @return [Array[untyped], nil]
          # :reek:NilCheck -- nil distinguishes "not a usable JWK" (undefined) from "[] empty set" (false).
          def self.keys(json_string)
            entries = jwk_entries(JSON.parse(json_string))
            entries.nil? ? nil : build_keys(entries)
          rescue JSON::ParserError
            nil
          end

          # The built keys, or nil if any entry is unbuildable (so a JWK Set with one bad key is undefined).
          def self.build_keys(entries)
            built = entries.map { |entry| key_from(entry) }
            built.include?(nil) ? nil : built
          end
          private_class_method :build_keys

          # The JWK objects to try (a Set's `keys` array, or the document as a lone JWK), or nil when the
          # document is not a JWK shape (not an object, or a Set whose `keys` is not an array).
          def self.jwk_entries(parsed)
            return nil unless parsed.is_a?(Hash)
            return jwk_set(parsed["keys"]) if parsed.key?("keys")

            [parsed]
          end
          private_class_method :jwk_entries

          def self.jwk_set(keys)
            keys.is_a?(Array) ? keys : nil
          end
          private_class_method :jwk_set

          # One OpenSSL public key from a JWK object, or nil when the object is not a buildable PUBLIC key
          # (unknown `kty`, missing/garbled components, or private material — a `d` member). nil propagates
          # to keys as the unbuildable sentinel. A private JWK is uniformly rejected (-> undefined); OPA is
          # inconsistent here (it rejects RSA private JWKs but builds a public key from EC and OKP private
          # JWKs), so the gem is stricter in the safe direction on the EC/OKP cases.
          def self.key_from(jwk)
            return nil unless jwk.is_a?(Hash) && !jwk.key?("d")

            case jwk["kty"]
            when "RSA" then rsa_key(jwk)
            when "EC" then ec_key(jwk)
            when "OKP" then okp_key(jwk)
            end
          rescue OpenSSL::OpenSSLError, ::ArgumentError, ::TypeError, KeyError
            nil
          end
          private_class_method :key_from

          # @return [OpenSSL::PKey::RSA]
          def self.rsa_key(jwk)
            public_key_from(
              OpenSSL::ASN1::Sequence([rsa_algorithm, rsa_public_bits(jwk)])
            )
          end
          private_class_method :rsa_key

          def self.rsa_algorithm
            OpenSSL::ASN1::Sequence(
              [OpenSSL::ASN1::ObjectId("rsaEncryption"), OpenSSL::ASN1::Null(nil)]
            )
          end
          private_class_method :rsa_algorithm

          def self.rsa_public_bits(jwk)
            modulus = bn(jwk["n"])
            exponent = bn(jwk["e"])
            OpenSSL::ASN1::BitString(
              OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(modulus), OpenSSL::ASN1::Integer(exponent)]).to_der
            )
          end
          private_class_method :rsa_public_bits

          # @return [OpenSSL::PKey::EC]
          def self.ec_key(jwk)
            curve = EC_CURVES.fetch(jwk["crv"])
            point = "\x04".b + segment(jwk["x"]) + segment(jwk["y"])
            public_key_from(OpenSSL::ASN1::Sequence([ec_algorithm(curve), OpenSSL::ASN1::BitString(point)]))
          end
          private_class_method :ec_key

          def self.ec_algorithm(curve)
            OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("id-ecPublicKey"), OpenSSL::ASN1::ObjectId(curve)])
          end
          private_class_method :ec_algorithm

          # @return [OpenSSL::PKey::PKey, nil]
          def self.okp_key(jwk)
            return nil unless jwk["crv"] == "Ed25519"

            OpenSSL::PKey.new_raw_public_key("ED25519", segment(jwk["x"]))
          end
          private_class_method :okp_key

          # @return [OpenSSL::PKey::PKey]
          def self.public_key_from(spki)
            OpenSSL::PKey.read(spki.to_der)
          end
          private_class_method :public_key_from

          # A base64url JWK component as a big-endian OpenSSL::BN.
          def self.bn(component)
            OpenSSL::BN.new(segment(component).unpack1("H*").to_s, 16)
          end
          private_class_method :bn

          # The raw bytes of one base64url JWK component (strict alphabet, padding optional). A missing or
          # non-string component (an incomplete JWK) raises ArgumentError, which key_from maps to a
          # skipped key — so an unbuildable JWK is undefined, never a NoMethodError out of the registry.
          def self.segment(component)
            raise ::ArgumentError, "JWK component must be a string" unless component.is_a?(String)

            Base64Url.strict_decode(component)
          end
          private_class_method :segment
        end
      end
    end
  end
end
