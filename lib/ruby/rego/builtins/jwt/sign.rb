# frozen_string_literal: true

require "json"
require "openssl"
require "base64"
require "strscan"
require_relative "../codecs"
require_relative "jwk"

# rubocop:disable Metrics/ModuleLength
module Ruby
  module Rego
    module Builtins
      # io.jwt.encode_sign(headers, payload, key) and io.jwt.encode_sign_raw(headers, payload, key): build a
      # signed compact JWS "b64(headers).b64(payload).b64(signature)", matching OPA's builtinJWTEncodeSign.
      # encode_sign takes Rego OBJECTS and serialises each with sorted keys and Go HTML escaping of <>&
      # and U+2028/U+2029 (Codecs.canonical_json — OPA signs those exact bytes); encode_sign_raw takes JSON
      # STRINGS and base64url-encodes them verbatim, but still validates each is JSON. The key is a JWK with private
      # material (an `oct` secret for HS*, or RSA/EC/OKP private params); the signing algorithm comes from
      # the header `alg`. An unsupported/absent alg, a non-JSON header or payload, or a key that does not
      # match the algorithm (wrong kty, missing private material) is undefined. ES*/PS* signatures are
      # randomised (not byte-reproducible); HS*/RS*/EdDSA are deterministic.
      # :reek:TooManyConstants -- the algorithm table plus the signer dispatch are distinct compat data.
      module Jwt
        # JWS `alg` header value -> { digest, scheme, kty }. Keyed by the on-the-wire alg name (distinct
        # from VERIFY_ALGORITHMS's builtin-name keys, same underlying data).
        JWS_ALGORITHMS = {
          "HS256" => { digest: "SHA256", scheme: :hmac, kty: "oct" },
          "HS384" => { digest: "SHA384", scheme: :hmac, kty: "oct" },
          "HS512" => { digest: "SHA512", scheme: :hmac, kty: "oct" },
          "RS256" => { digest: "SHA256", scheme: :rsa, kty: "RSA" },
          "RS384" => { digest: "SHA384", scheme: :rsa, kty: "RSA" },
          "RS512" => { digest: "SHA512", scheme: :rsa, kty: "RSA" },
          "PS256" => { digest: "SHA256", scheme: :pss, kty: "RSA" },
          "PS384" => { digest: "SHA384", scheme: :pss, kty: "RSA" },
          "PS512" => { digest: "SHA512", scheme: :pss, kty: "RSA" },
          "ES256" => { digest: "SHA256", scheme: :ecdsa, kty: "EC" },
          "ES384" => { digest: "SHA384", scheme: :ecdsa, kty: "EC" },
          "ES512" => { digest: "SHA512", scheme: :ecdsa, kty: "EC" },
          "EdDSA" => { digest: nil, scheme: :eddsa, kty: "OKP" }
        }.freeze

        ENCODE_FUNCTIONS = {
          "io.jwt.encode_sign" => { arity: 3, handler: :encode_sign },
          "io.jwt.encode_sign_raw" => { arity: 3, handler: :encode_sign_raw }
        }.freeze

        # scheme -> the signer for one asymmetric private key.
        SIGNERS = { rsa: :rsa_sign, pss: :pss_sign, ecdsa: :ecdsa_sign, eddsa: :eddsa_sign }.freeze

        # The context for an undefined raised in the shared encode/sign path (front-ends use their own
        # builtin name for their input validation); the value only feeds the internal error message.
        ENCODE_CONTEXT = "io.jwt.encode_sign"

        # One JSON string literal: a quote, any run of escapes (\\.) or non-quote/non-backslash bytes, a
        # quote. Shared by every JSON scan below — first_alg's value reader, the container skipper, and the
        # comment gate — so each consumes a string token whole and never mistakes its contents for syntax.
        JSON_STRING_TOKEN = /"(?:\\.|[^"\\])*"/

        # json >= 2.14 added the allow_duplicate_key keyword; the gemspec allows json ~> 2.0, where the
        # keyword is unknown and JSON.parse would raise ArgumentError (escaping the totality boundary).
        # Probe once so the validity gate can keep a repeated key valid on json that supports it (OPA
        # accepts dup keys; first_alg selects, and json 3.0 would otherwise raise) and fall back to the
        # plain parse on older json, whose default already accepts duplicate keys.
        DUP_KEY_SUPPORTED = begin
          JSON.parse("{}", allow_duplicate_key: true)
          true
        rescue ::ArgumentError
          false
        end

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register_encoders!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, ENCODE_FUNCTIONS)
          registry
        end

        # @param headers_value [Ruby::Rego::Value] header object
        # @param payload_value [Ruby::Rego::Value] payload object
        # @param key_value [Ruby::Rego::Value] JWK object with private material
        # @return [Ruby::Rego::StringValue]
        def self.encode_sign(headers_value, payload_value, key_value)
          encode(Codecs.canonical_json(headers_value), Codecs.canonical_json(payload_value), key_value.to_ruby)
        end

        # @param headers_value [Ruby::Rego::Value] header JSON string
        # @param payload_value [Ruby::Rego::Value] payload JSON string
        # @param key_value [Ruby::Rego::Value] JWK JSON string
        # @return [Ruby::Rego::StringValue]
        def self.encode_sign_raw(headers_value, payload_value, key_value)
          context = "io.jwt.encode_sign_raw"
          encode(json_string(headers_value, context), json_string(payload_value, context),
                 parse_jwk(key_value, context))
        end

        # Assembles b64(headers).b64(payload).b64(signature) once the algorithm and key are resolved.
        def self.encode(header_json, payload_json, jwk)
          config = header_algorithm(header_json)
          signing_input = "#{b64(header_json)}.#{b64(payload_json)}"
          StringValue.new("#{signing_input}.#{b64(sign(config, jwk, signing_input))}")
        end
        private_class_method :encode

        # The JWS_ALGORITHMS config for the header's `alg`, or undefined when the header is not a JSON
        # object, has no `alg`, or names an unsupported algorithm (including "none").
        # :reek:NilCheck
        def self.header_algorithm(header_json)
          config = configured_algorithm(header_json)
          config.nil? ? undefined!(ENCODE_CONTEXT) : config
        end
        private_class_method :header_algorithm

        # :reek:NilCheck
        def self.configured_algorithm(header_json)
          alg = first_alg(header_json)
          alg && JWS_ALGORITHMS[alg]
        rescue JSON::ParserError
          nil
        end
        private_class_method :configured_algorithm

        # The value of the FIRST top-level `alg` member. OPA/Go select the first occurrence when a header
        # repeats `alg`, but Ruby's JSON.parse keeps the last (and its C parser collapses duplicates
        # before any object hook), so `{"alg":"none","alg":"HS256"}` would sign here while OPA refuses it.
        # The header is already valid JSON at this point (validated by json_string / produced by
        # canonical_json), so this only locates the first depth-1 `alg`; nil when the header is not an
        # object or has no string-valued `alg` (-> unsupported algorithm -> undefined).
        # Leading whitespace is folded into each delimiter regexp so the scan stays Regexp-typed. The
        # `eos?` guard bounds the loop independently of the JSON being well-formed (totality), so it
        # stays even though a valid object always closes with `}`.
        # rubocop:disable Metrics/MethodLength
        # :reek:NilCheck :reek:TooManyStatements
        def self.first_alg(header_json)
          scanner = StringScanner.new(header_json)
          return nil unless scanner.scan(/\s*\{/)

          until scanner.eos?
            break if scanner.scan(/\s*\}/)

            key = member_key(scanner)
            return nil if key.nil?
            return scan_string(scanner) if key == "alg"

            skip_value(scanner)
            break unless scanner.scan(/\s*,/)
          end
          nil
        end
        private_class_method :first_alg
        # rubocop:enable Metrics/MethodLength

        # The key of the member at the cursor, having consumed it and its `:`, or nil when no
        # `"key":` is there. The header is valid JSON, so a non-nil key is always followed by its value.
        # :reek:NilCheck
        def self.member_key(scanner)
          key = scan_string(scanner)
          key if key && scanner.scan(/\s*:/)
        end
        private_class_method :member_key

        # One JSON string token (skipping leading whitespace) decoded, or nil when none is at the cursor.
        # :reek:NilCheck
        def self.scan_string(scanner)
          token = scanner.scan(/\s*#{JSON_STRING_TOKEN}/o)
          token && JSON.parse(token)
        end
        private_class_method :scan_string

        # Advance the scanner past one JSON value (object/array/string/number/literal). The header is valid
        # JSON, so every value is well-formed; on anything else the scanner simply stops where it is.
        def self.skip_value(scanner)
          scanner.skip(/\s*/)
          case scanner.peek(1)
          when '"' then scan_string(scanner)
          when "{", "[" then skip_container(scanner)
          else scanner.scan(/[^,}\]]+/)
          end
        end
        private_class_method :skip_value

        # Skip a balanced {...} or [...], honouring string contents. Each step consumes either a whole
        # string token or one character, tracking nesting depth until the opening bracket is closed.
        def self.skip_container(scanner)
          depth = 0
          until scanner.eos?
            token = scanner.scan(/#{JSON_STRING_TOKEN}|./mo)
            depth += 1 if ["{", "["].include?(token)
            depth -= 1 if ["}", "]"].include?(token)
            break if depth.zero?
          end
        end
        private_class_method :skip_container

        # The raw signature bytes over `signing_input`, or undefined when the key does not match the
        # algorithm (wrong kty / missing or malformed private material).
        # :reek:NilCheck
        def self.sign(config, jwk, signing_input)
          signature = signature_bytes(config, jwk, signing_input)
          signature.nil? ? undefined!(ENCODE_CONTEXT) : signature
        end
        private_class_method :sign

        # nil when the JWK's kty does not match the algorithm, or signing fails.
        def self.signature_bytes(config, jwk, signing_input)
          return nil unless jwk.is_a?(Hash) && jwk["kty"] == config[:kty]

          if config[:scheme] == :hmac
            hmac_sign(config[:digest], jwk, signing_input)
          else
            asymmetric_sign(config, jwk, signing_input)
          end
        end
        private_class_method :signature_bytes

        # @return [String, nil]
        def self.hmac_sign(digest, jwk, signing_input)
          secret = Jwk.oct_secret(jwk)
          secret && OpenSSL::HMAC.digest(digest, secret, signing_input)
        rescue OpenSSL::OpenSSLError
          nil
        end
        private_class_method :hmac_sign

        # @return [String, nil]
        # :reek:NilCheck
        def self.asymmetric_sign(config, jwk, signing_input)
          key = Jwk.private_key(jwk)
          return nil if key.nil?

          send(SIGNERS.fetch(config[:scheme]), config[:digest], key, signing_input)
        rescue OpenSSL::OpenSSLError
          nil
        end
        private_class_method :asymmetric_sign

        # @return [String]
        def self.rsa_sign(digest, key, signing_input)
          key.sign(OpenSSL::Digest.new(digest), signing_input)
        end
        private_class_method :rsa_sign

        # RSA-PSS with salt length = digest length and MGF1 = the message digest, as OPA emits.
        # @return [String]
        def self.pss_sign(digest, key, signing_input)
          key.sign_pss(digest, signing_input, salt_length: :digest, mgf1_hash: digest)
        end
        private_class_method :pss_sign

        # ECDSA signs to DER; JWS wants the fixed-width r‖s pair (the inverse of verify's ecdsa_der).
        # @return [String]
        def self.ecdsa_sign(digest, key, signing_input)
          ecdsa_raw(key.sign(OpenSSL::Digest.new(digest), signing_input), key)
        end
        private_class_method :ecdsa_sign

        # @return [String]
        def self.eddsa_sign(_digest, key, signing_input)
          key.sign(nil, signing_input)
        end
        private_class_method :eddsa_sign

        # The r‖s fixed-width form of a DER ECDSA-Sig-Value (the signature is the gem's own, not attacker
        # input, so ASN1.decode is safe). Each half is left-padded to the curve's coordinate width.
        # @return [String]
        def self.ecdsa_raw(der, key)
          width = (key.group.degree + 7) / 8
          values = OpenSSL::ASN1.decode(der).value
          half(values[0], width) + half(values[1], width)
        end
        private_class_method :ecdsa_raw

        # One ECDSA-Sig-Value INTEGER as `width` big-endian bytes.
        def self.half(integer, width)
          integer.value.to_s(2).rjust(width, "\x00".b)
        end
        private_class_method :half

        # The string is valid JSON; returns it verbatim (encode_sign_raw base64url-encodes the raw bytes).
        def self.json_string(value, context)
          string = string_value(value, context)
          strict_json_parse(string)
          string
        rescue JSON::ParserError
          undefined!(context)
        end
        private_class_method :json_string

        # The JWK object parsed from a JSON string (encode_sign_raw's key argument).
        def self.parse_jwk(value, context)
          strict_json_parse(string_value(value, context))
        rescue JSON::ParserError
          undefined!(context)
        end
        private_class_method :parse_jwk

        # Parse like Go's encoding/json (OPA's parser), rejecting the `//` and `/* */` comments that
        # Ruby's json gem accepts but Go does not — otherwise encode_sign_raw would emit a SIGNED token
        # for a header/payload/key OPA refuses (gem-more-lenient). Comments inside string VALUES are
        # legal JSON and must survive, so a comment is only rejected in STRUCTURAL position (outside any
        # string token); contains_json_comment? makes that distinction. Ruby's parser does not accept
        # `#` comments, so only the two C-style forms leak.
        # @raise [JSON::ParserError] on a bad encoding, a structural comment, or otherwise-invalid JSON
        # The encoding guard mirrors io.jwt.decode: a string that is not ascii-compatible-and-valid (e.g.
        # UTF-16, or invalid UTF-8) would make StringScanner#scan with an ASCII/UTF-8 regexp raise
        # Encoding::CompatibilityError / ArgumentError out of contains_json_comment? (and first_alg) — not
        # JSON::ParserError — and so escape the registry's totality boundary. Mapping it to undefined here
        # keeps every downstream scan on a safe string. The parse keeps a repeated key valid (OPA/Go accept
        # it, taking the first — first_alg does the selection) via DUP_KEY_SUPPORTED.
        def self.strict_json_parse(string)
          usable_encoding = string.encoding.ascii_compatible? && string.valid_encoding?
          raise JSON::ParserError, "invalid string encoding" unless usable_encoding
          raise JSON::ParserError, "comments are not valid JSON" if contains_json_comment?(string)
          return JSON.parse(string, allow_duplicate_key: true) if DUP_KEY_SUPPORTED

          JSON.parse(string)
        end
        private_class_method :strict_json_parse

        # True when `//` or `/* */` appears in STRUCTURAL position (not inside a string value). Scans the
        # string token-aware: a `"..."` (honouring `\"` escapes) is consumed whole so its bytes can never
        # be mistaken for a comment opener; outside a string, a `/` followed by `/` or `*` is a comment.
        def self.contains_json_comment?(string)
          scanner = StringScanner.new(string)
          until scanner.eos?
            next if scanner.scan(/#{JSON_STRING_TOKEN}/o)
            return true if scanner.scan(%r{//|/\*})

            scanner.getch
          end
          false
        end
        private_class_method :contains_json_comment?

        # base64url without padding, as JWS segments use.
        def self.b64(bytes)
          Base64.urlsafe_encode64(bytes, padding: false)
        end
        private_class_method :b64
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength
