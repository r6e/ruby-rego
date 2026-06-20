# frozen_string_literal: true

require "json"
require "openssl"
require_relative "../base64url"

# rubocop:disable Metrics/ModuleLength
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
            return nil unless json_string.encoding.ascii_compatible? && json_string.valid_encoding?

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
          rescue OpenSSL::OpenSSLError, ::ArgumentError, ::TypeError, ::KeyError
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
            point = ec_uncompressed_point(jwk)
            public_key_from(OpenSSL::ASN1::Sequence([ec_algorithm(curve), OpenSSL::ASN1::BitString(point)]))
          end
          private_class_method :ec_key

          # The SEC1 uncompressed EC point 0x04‖x‖y from a JWK's x/y coordinates.
          def self.ec_uncompressed_point(jwk)
            "\x04".b + segment(jwk["x"]) + segment(jwk["y"])
          end
          private_class_method :ec_uncompressed_point

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

          # The HMAC secret bytes of an `oct` JWK (the base64url `k`), or nil when the JWK is not a usable
          # oct key — including an EMPTY `k`, which OPA rejects (an empty HMAC secret is undefined, not a
          # signable key). For io.jwt.encode_sign's HS* algorithms, which key on the raw secret. A `k` using
          # the standard-base64 '+'/'/' alphabet is undefined here (strict base64url) where OPA is lenient
          # — a safe, gem-stricter divergence (the JWK spec mandates base64url).
          # :reek:NilCheck
          def self.oct_secret(jwk)
            return nil unless jwk.is_a?(Hash) && jwk["kty"] == "oct"

            secret = segment(jwk["k"])
            secret unless secret.empty?
          rescue OpenSSL::OpenSSLError, ::ArgumentError, ::TypeError
            nil
          end

          # An OpenSSL PRIVATE key from an RSA/EC/OKP JWK carrying private material, or nil when the JWK is
          # not a buildable private key. For io.jwt.encode_sign's asymmetric algorithms.
          # :reek:NilCheck
          def self.private_key(jwk)
            return nil unless jwk.is_a?(Hash)

            case jwk["kty"]
            when "RSA" then rsa_private(jwk)
            when "EC" then ec_private(jwk)
            when "OKP" then okp_private(jwk)
            end
          rescue OpenSSL::OpenSSLError, ::ArgumentError, ::TypeError, ::KeyError
            nil
          end

          # @return [OpenSSL::PKey::RSA] from the JWK's n/e/d/p/q (dp/dq/qi are derived). OPA validates the
          # key (Go's rsa.Validate), so an inconsistent d/e or supplied dp/dq/qi is rejected.
          def self.rsa_private(jwk)
            validate_rsa!(jwk)
            OpenSSL::PKey::RSA.new(rsa_private_der(jwk))
          end
          private_class_method :rsa_private

          def self.rsa_private_der(jwk)
            OpenSSL::ASN1::Sequence(rsa_private_fields(jwk).map { |field| OpenSSL::ASN1::Integer(field) }).to_der
          end
          private_class_method :rsa_private_der

          # The RSAPrivateKey integer fields [version, n, e, d, p, q, dp, dq, qi].
          def self.rsa_private_fields(jwk)
            exponent = bn(jwk["d"])
            primes = [bn(jwk["p"]), bn(jwk["q"])]
            [0, bn(jwk["n"]), bn(jwk["e"]), exponent] + primes + crt_params(exponent, primes)
          end
          private_class_method :rsa_private_fields

          # The [dp, dq, qi] CRT exponents/coefficient derived from d and the primes [p, q].
          def self.crt_params(exponent, primes)
            p_prime, q_prime = primes
            one = OpenSSL::BN.new(1)
            [exponent % (p_prime - one), exponent % (q_prime - one), q_prime.mod_inverse(p_prime)]
          end
          private_class_method :crt_params

          # OPA validates the private RSA key (Go's rsa.Validate + jwx CRT check); raise ArgumentError
          # (-> undefined) when the modulus/exponent are inconsistent or supplied dp/dq/qi disagree.
          def self.validate_rsa!(jwk)
            primes = [bn(jwk["p"]), bn(jwk["q"])]
            unless valid_exponent?(bn(jwk["e"])) && rsa_consistent?(jwk, primes)
              raise ::ArgumentError, "inconsistent RSA key"
            end

            validate_crt!(jwk)
          end
          private_class_method :validate_rsa!

          # Go's minimum signing key size (crypto/rsa rejects a modulus below this).
          RSA_MIN_MODULUS_BITS = 1024
          # Go's checkPub bounds the public exponent to 2 <= e <= 2^31-1; OpenSSL signs with any e (incl.
          # e=1, the identity), so OPA rejects keys outside this range that the gem would otherwise sign.
          RSA_MIN_EXPONENT = OpenSSL::BN.new(2)
          RSA_MAX_EXPONENT = OpenSSL::BN.new(((2**31) - 1).to_s)

          # @return [bool] the modulus is >= 1024 bits (Go's signing floor), n == p*q, and e*d ≡ 1 mod p-1
          # and mod q-1 (rsa.Validate). OpenSSL signs via the CRT primes and never checks n or the size, so
          # both must be enforced here; the public-exponent range is checked separately in validate_rsa!.
          def self.rsa_consistent?(jwk, primes)
            one = OpenSSL::BN.new(1)
            modulus = bn(jwk["n"])
            product = bn(jwk["e"]) * bn(jwk["d"])
            modulus.num_bits >= RSA_MIN_MODULUS_BITS && modulus == primes[0] * primes[1] &&
              primes.all? { |prime| product % (prime - one) == one }
          end
          private_class_method :rsa_consistent?

          # @return [bool] e is within Go checkPub's 2..2^31-1 range.
          def self.valid_exponent?(exponent)
            exponent.between?(RSA_MIN_EXPONENT, RSA_MAX_EXPONENT)
          end
          private_class_method :valid_exponent?

          # OPA validates dp/dq/qi only when ALL THREE are present (then rejects any mismatch); with fewer
          # present it ignores them and derives its own.
          def self.validate_crt!(jwk)
            return unless %w[dp dq qi].all? { |field| jwk.key?(field) }

            crt = crt_params(bn(jwk["d"]), [bn(jwk["p"]), bn(jwk["q"])])
            raise ::ArgumentError, "inconsistent CRT parameters" unless [bn(jwk["dp"]), bn(jwk["dq"]),
                                                                         bn(jwk["qi"])] == crt
          end
          private_class_method :validate_crt!

          # @return [OpenSSL::PKey::EC] from the JWK's curve and x/y/d. OPA requires d to be the curve's
          # fixed coordinate width and the scalar in [1, order-1]; otherwise the key is undefined.
          def self.ec_private(jwk)
            group = OpenSSL::PKey::EC::Group.new(EC_CURVES.fetch(jwk["crv"]))
            private_bytes = segment(jwk["d"])
            validate_ec_scalar!(private_bytes, group)
            point = ec_uncompressed_point(jwk)
            OpenSSL::PKey::EC.new(ec_private_der(group.curve_name, point, private_bytes))
          end
          private_class_method :ec_private

          # d must be exactly the coordinate width — OPA/Go reject a scalar shorter or longer than the
          # curve's fixed width (a correctly-left-padded full-width d is fine) — and in [1, order-1].
          def self.validate_ec_scalar!(private_bytes, group)
            scalar = OpenSSL::BN.new(private_bytes.unpack1("H*").to_s, 16)
            in_range = scalar >= OpenSSL::BN.new(1) && scalar < group.order
            return if private_bytes.bytesize == (group.degree + 7) / 8 && in_range

            raise ::ArgumentError, "invalid EC scalar"
          end
          private_class_method :validate_ec_scalar!

          # An RFC 5915 ECPrivateKey DER: SEQUENCE { version, privateKey, [0] curve oid, [1] public point }.
          def self.ec_private_der(curve, point, private_bytes)
            OpenSSL::ASN1::Sequence([
                                      OpenSSL::ASN1::Integer(1),
                                      OpenSSL::ASN1::OctetString(private_bytes),
                                      OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId(curve)], 0,
                                                                  :CONTEXT_SPECIFIC),
                                      OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::BitString(point)], 1,
                                                                  :CONTEXT_SPECIFIC)
                                    ]).to_der
          end
          private_class_method :ec_private_der

          # @return [OpenSSL::PKey::PKey, nil] an Ed25519 private key from the JWK's raw `d`. OPA requires a
          # matching public `x`, so a missing or inconsistent `x` makes the key undefined.
          # :reek:NilCheck
          def self.okp_private(jwk)
            return nil unless jwk["crv"] == "Ed25519"

            key = OpenSSL::PKey.new_raw_private_key("ED25519", segment(jwk["d"]))
            key if key.raw_public_key == segment(jwk["x"])
          end
          private_class_method :okp_private

          # A base64url JWK component as a big-endian OpenSSL::BN.
          def self.bn(component)
            OpenSSL::BN.new(segment(component).unpack1("H*").to_s, 16)
          end
          private_class_method :bn

          # The raw bytes of one base64url JWK component (strict alphabet, padding optional). A missing or
          # non-string component (an incomplete JWK) raises ArgumentError, which key_from maps to a
          # skipped key — so an unbuildable JWK is undefined, never a NoMethodError out of the registry.
          # A non-ascii-compatible or invalid-encoding component is rejected the same way: otherwise
          # Base64Url.strict_decode's Regexp match would raise Encoding::CompatibilityError out of the
          # private_key/oct_secret rescues (which catch ArgumentError, not EncodingError) and escape the
          # registry's totality boundary on a private JWK built from such a component.
          def self.segment(component)
            usable = component.is_a?(String) && component.encoding.ascii_compatible? && component.valid_encoding?
            raise ::ArgumentError, "JWK component must be a usable string" unless usable

            Base64Url.strict_decode(component)
          end
          private_class_method :segment
        end
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength
