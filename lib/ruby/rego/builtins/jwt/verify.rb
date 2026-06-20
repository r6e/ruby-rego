# frozen_string_literal: true

require "openssl"
require_relative "../base64url"
require_relative "jwk"

# rubocop:disable Metrics/ModuleLength
module Ruby
  module Rego
    module Builtins
      # io.jwt.verify_{hs,rs,ps,es}{256,384,512} and io.jwt.verify_eddsa: verify a compact JWS's
      # signature against a key, returning a boolean. The result mirrors OPA's builtinJWTVerify exactly,
      # including its three-way outcome:
      #   * undefined — the token is not three segments, its signature segment is not base64url, or (for
      #     asymmetric algorithms) no usable public key can be parsed (a private/unsupported key, a
      #     malformed key, or a JWK Set in which any key is unbuildable);
      #   * false — the token and key are well-formed but the signature does not verify (wrong key, wrong
      #     key type, wrong-length ECDSA signature; the header alg is ignored; for HMAC an empty secret is
      #     a normal, failing key — false, not undefined; an empty JWK Set has no key to try — false);
      #   * true — the signature verifies.
      # Like OPA, verification needs only the signing input bytes (header.payload), the decoded signature,
      # and the key — the header and payload are NOT parsed, so a token whose segments are not JSON
      # objects still verifies. Asymmetric keys are a PEM certificate, a PKIX/SPKI public key, or a JWK /
      # JWK Set (see Jwt::Jwk); a JWK Set verifies if any of its keys does but is undefined if any key is
      # unbuildable.
      # :reek:TooManyConstants -- the verify config (algorithm/verifier tables) plus the PEM-dispatch
      # constants (BEGIN/trailer regexes, NIST curve allowlist, Ed25519 oid) are each a distinct
      # compatibility datum.
      module Jwt
        VERIFY_ALGORITHMS = {
          "io.jwt.verify_hs256" => { digest: "SHA256", scheme: :hmac },
          "io.jwt.verify_hs384" => { digest: "SHA384", scheme: :hmac },
          "io.jwt.verify_hs512" => { digest: "SHA512", scheme: :hmac },
          "io.jwt.verify_rs256" => { digest: "SHA256", scheme: :rsa },
          "io.jwt.verify_rs384" => { digest: "SHA384", scheme: :rsa },
          "io.jwt.verify_rs512" => { digest: "SHA512", scheme: :rsa },
          "io.jwt.verify_ps256" => { digest: "SHA256", scheme: :pss },
          "io.jwt.verify_ps384" => { digest: "SHA384", scheme: :pss },
          "io.jwt.verify_ps512" => { digest: "SHA512", scheme: :pss },
          "io.jwt.verify_es256" => { digest: "SHA256", scheme: :ecdsa },
          "io.jwt.verify_es384" => { digest: "SHA384", scheme: :ecdsa },
          "io.jwt.verify_es512" => { digest: "SHA512", scheme: :ecdsa },
          "io.jwt.verify_eddsa" => { digest: nil, scheme: :eddsa }
        }.freeze

        VERIFY_FUNCTIONS = VERIFY_ALGORITHMS.keys.to_h do |name|
          [name, { arity: 2, handler: name.split(".").last.to_sym }]
        end.freeze

        # scheme -> the verifier method for one asymmetric public key.
        VERIFIERS = { rsa: :rsa_verified?, pss: :pss_verified?, ecdsa: :ecdsa_verified?, eddsa: :eddsa_verified? }
                    .freeze

        # The first PEM BEGIN marker, capturing the type label. A plain char class with no backreference,
        # so matching is linear (the original block-spanning regex backtracked O(n^2) on many BEGIN lines).
        PEM_BEGIN = /-----BEGIN ([A-Z0-9 ]+)-----/
        # What may follow the END marker for the block to be the sole content, mirroring Go's pem.Decode:
        # the END line's own trailing spaces/tabs and at most one line terminator (\n or \r\n) — a bare
        # \r, a second newline, or any other text is trailing data and makes the key undefined.
        PEM_TRAILER = /\A[ \t]*(?:\r\n|\n)?\z/
        # OpenSSL curve names Go's x509.ParsePKIXPublicKey accepts (the NIST P-curves); secp256k1 and the
        # brainpool curves are rejected by OPA.
        NIST_EC_CURVES = %w[secp224r1 prime256v1 secp384r1 secp521r1].freeze
        # The OpenSSL oid of an Ed25519 key (a bare OpenSSL::PKey::PKey, distinguishing it from a
        # similarly-bare RSASSA-PSS or post-quantum key, which OPA's x509 parser rejects).
        ED25519_OID = "ED25519"

        # Each verify_* builtin is a thin delegation to `verify` carrying its own name (the algorithm
        # config key); the algorithms differ only by data in VERIFY_ALGORITHMS.
        VERIFY_ALGORITHMS.each_key do |name|
          define_singleton_method(name.split(".").last) { |jwt, key| verify(jwt, key, name) }
        end

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register_verifications!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, VERIFY_FUNCTIONS)
          registry
        end

        # @param jwt_value [Ruby::Rego::Value]
        # @param key_value [Ruby::Rego::Value]
        # @param context [String] the builtin name / VERIFY_ALGORITHMS key
        # @return [Ruby::Rego::BooleanValue]
        # :reek:NilCheck -- a nil scheme_result is the undefined sentinel (empty/unparseable key).
        def self.verify(jwt_value, key_value, context)
          config = VERIFY_ALGORITHMS.fetch(context)
          signed = split_signed(string_value(jwt_value, context), context)
          result = scheme_result(config, string_value(key_value, context), signed)
          result.nil? ? undefined!(context) : BooleanValue.new(result)
        end

        # Splits a compact JWS into [signing_input, raw signature bytes]. A token that is not three
        # base64url segments, or whose signature is not strict base64url, is undefined — matching OPA,
        # which errors (rather than returning false) on a structurally invalid token.
        # :reek:NilCheck -- nil from three_segments is the structural-failure sentinel.
        def self.split_signed(token, context)
          parts = three_segments(token)
          undefined!(context) if parts.nil?

          ["#{parts[0]}.#{parts[1]}", decode_signature(parts[2], context)]
        end
        private_class_method :split_signed

        # The token's three segments, or nil when it is not ascii-compatible/valid (split/Regexp would
        # raise) or is not exactly three segments.
        def self.three_segments(token)
          return unless token.encoding.ascii_compatible? && token.valid_encoding?

          parts = token.split(".", -1)
          parts if parts.length == 3
        end
        private_class_method :three_segments

        def self.decode_signature(segment, context)
          Base64Url.strict_decode(segment)
        rescue ::ArgumentError
          undefined!(context)
        end
        private_class_method :decode_signature

        # true/false verification result, or nil (the undefined sentinel) when — for asymmetric algorithms
        # — no key can be parsed. HMAC verifies against the secret directly (an empty secret is a normal,
        # failing key, matching OPA — not undefined); asymmetric algorithms verify true if any candidate
        # key verifies.
        def self.scheme_result(config, key, signed)
          return hmac_verified?(config[:digest], key, signed) if config[:scheme] == :hmac

          asymmetric_result(config, key, signed)
        end
        private_class_method :scheme_result

        # nil (undefined) when the key string is not a usable public key; otherwise true if any candidate
        # key verifies. An empty JWK Set yields [] candidates, so .any? is false (matching OPA), while a
        # non-key / unbuildable key yields nil candidates -> undefined.
        # :reek:NilCheck
        def self.asymmetric_result(config, key, signed)
          candidates = public_keys(key)
          return nil if candidates.nil?

          candidates.any? { |pkey| asymmetric_verified?(config, pkey, signed) }
        end
        private_class_method :asymmetric_result

        # @param signed [Array(String, String)] [signing_input, signature]
        # @return [bool]
        def self.hmac_verified?(digest, secret, signed)
          signing_input, signature = signed
          expected = OpenSSL::HMAC.digest(digest, secret, signing_input)
          OpenSSL.secure_compare(expected, signature)
        rescue OpenSSL::OpenSSLError
          false
        end
        private_class_method :hmac_verified?

        # Any verification-time failure — wrong key type, malformed ECDSA signature, padding mismatch — is
        # false, not undefined: the key parsed, the signature just does not verify.
        # @return [bool]
        def self.asymmetric_verified?(config, pkey, signed)
          send(VERIFIERS.fetch(config[:scheme]), config[:digest], pkey, signed)
        rescue OpenSSL::OpenSSLError, ::NoMethodError
          false
        end
        private_class_method :asymmetric_verified?

        # @return [bool]
        def self.rsa_verified?(digest, pkey, signed)
          signing_input, signature = signed
          pkey.verify(OpenSSL::Digest.new(digest), signature, signing_input)
        end
        private_class_method :rsa_verified?

        # RSA-PSS with salt length auto-detected from the signature (Go's rsa.PSSSaltLengthAuto) and the
        # MGF1 hash equal to the message digest, as in OPA.
        # @return [bool]
        def self.pss_verified?(digest, pkey, signed)
          signing_input, signature = signed
          pkey.verify_pss(digest, signature, signing_input, salt_length: :auto, mgf1_hash: digest)
        end
        private_class_method :pss_verified?

        # JWS ECDSA signatures are the fixed-width r‖s pair (2 * the curve's coordinate width), not DER; a
        # wrong-width signature simply does not verify (false). r‖s is re-encoded as a DER ECDSA-Sig-Value
        # for OpenSSL.
        # @return [bool]
        def self.ecdsa_verified?(digest, pkey, signed)
          signing_input, signature = signed
          width = (pkey.group.degree + 7) / 8
          return false unless signature.bytesize == width * 2

          pkey.verify(OpenSSL::Digest.new(digest), ecdsa_der(signature, width), signing_input)
        end
        private_class_method :ecdsa_verified?

        # @return [bool]
        def self.eddsa_verified?(_digest, pkey, signed)
          signing_input, signature = signed
          pkey.verify(nil, signature, signing_input)
        end
        private_class_method :eddsa_verified?

        # @return [String] DER ECDSA-Sig-Value of the r‖s halves of `signature`.
        def self.ecdsa_der(signature, width)
          OpenSSL::ASN1::Sequence([
                                    OpenSSL::ASN1::Integer(coordinate_bn(signature[0, width])),
                                    OpenSSL::ASN1::Integer(coordinate_bn(signature[width, width]))
                                  ]).to_der
        end
        private_class_method :ecdsa_der

        # One ECDSA signature half (big-endian) as an OpenSSL::BN.
        def self.coordinate_bn(bytes)
          OpenSSL::BN.new(bytes.to_s.unpack1("H*").to_s, 16)
        end
        private_class_method :coordinate_bn

        # Candidate public keys: [key] from a PEM certificate or PKIX/SPKI public key, or the JWK / JWK Set
        # list (nil when the string is not a usable key, [] for an empty JWK Set — see Jwk.keys). The PEM
        # form is dispatched by its single block's type, matching OPA's pem.Decode + x509.ParsePKIXPublicKey
        # exactly, so PKCS#1 "RSA PUBLIC KEY", private-key blocks, bare DER, trailing/extra blocks, and a
        # smuggled header are all excluded (they fall through to JWK parsing, which fails -> undefined).
        # :reek:NilCheck -- nil from pem_public_key falls through to JWK parsing.
        def self.public_keys(key)
          pem = pem_public_key(key)
          pem ? [pem] : Jwk.keys(key)
        end
        private_class_method :public_keys

        # The public key of the lone PEM block in `key`, dispatched by block type: a CERTIFICATE's key, or
        # a PKIX/SPKI PUBLIC KEY. nil for any other (or no) clean single block.
        def self.pem_public_key(key)
          case single_pem_block_type(key)
          when "CERTIFICATE" then certificate_key(key)
          when "PUBLIC KEY" then spki_public_key(key)
          end
        end
        private_class_method :pem_public_key

        # The type of the first PEM block when it is the only content (Go's pem.Decode: leading non-PEM
        # preamble is allowed, but the END marker must be followed only by its line's trailing whitespace
        # and one optional terminator — no further block or bytes), else nil. The encoding guard keeps the
        # match off invalid-UTF-8 / ASCII-incompatible bytes (Regexp#match would raise ArgumentError /
        # Encoding::CompatibilityError); such a key is simply not PEM.
        # :reek:NilCheck -- nil is the not-a-single-clean-PEM-block sentinel.
        def self.single_pem_block_type(key)
          return nil unless key.encoding.ascii_compatible? && key.valid_encoding?

          match = PEM_BEGIN.match(key)
          match && clean_block_type(key, match)
        end
        private_class_method :single_pem_block_type

        # The block type if `key` closes the BEGIN at `match` with a matching END whose only trailing
        # content is PEM_TRAILER, else nil. key.index is a linear forward scan (no regex backtracking).
        # `match.end(0) || 0` and `.to_s` only satisfy steep — at runtime the overall match always has an
        # end offset, and the slice (at most key.length) is never past the end, so neither falls back.
        # :reek:NilCheck -- nil when there is no clean matching END.
        def self.clean_block_type(key, match)
          type = match[1]
          end_marker = "-----END #{type}-----"
          end_at = key.index(end_marker, match.end(0) || 0)
          return nil if end_at.nil? || !key[(end_at + end_marker.length)..].to_s.match?(PEM_TRAILER)

          type
        end
        private_class_method :clean_block_type

        # Any OpenSSL error (not just CertificateError) means "not a usable certificate": #public_key on a
        # cert with a malformed/unsupported SPKI can raise a sibling PKeyError, and the exact class is not
        # contracted across OpenSSL versions; rescuing the superclass keeps it nil rather than escaping.
        def self.certificate_key(key)
          pkey = OpenSSL::X509::Certificate.new(key).public_key
          pkey if supported_public_key?(pkey)
        rescue OpenSSL::OpenSSLError
          nil
        end
        private_class_method :certificate_key

        # The key of a PKIX/SPKI "PUBLIC KEY" block, or nil. The "" passphrase stops OpenSSL prompting on
        # the TTY for an encrypted PEM (unreachable here — a private block is excluded by type — but cheap).
        def self.spki_public_key(key)
          pkey = OpenSSL::PKey.read(key, "")
          pkey if supported_public_key?(pkey)
        rescue OpenSSL::OpenSSLError, ::ArgumentError
          nil
        end
        private_class_method :spki_public_key

        # Whether the key is one OPA's x509.ParsePKIXPublicKey accepts: an RSA key, an EC key on a NIST
        # curve (P-224/256/384/521 — Go rejects secp256k1/brainpool), or an Ed25519 key (a bare PKey whose
        # oid is ED25519, excluding RSASSA-PSS and PQC bare-PKey types). DSA/DH fall through to false.
        def self.supported_public_key?(pkey)
          case pkey
          when OpenSSL::PKey::RSA then true
          when OpenSSL::PKey::EC then NIST_EC_CURVES.include?(pkey.group&.curve_name)
          else pkey.oid == ED25519_OID
          end
        end
        private_class_method :supported_public_key?

        # Maps a verification precondition failure to OPA's undefined.
        # @return [void]
        def self.undefined!(context)
          raise BuiltinArgumentError.new(
            "Invalid #{context} input",
            expected: "a three-segment JWS with a base64url signature and a usable key",
            actual: "invalid", context: context, location: nil
          )
        end
        private_class_method :undefined!
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength
