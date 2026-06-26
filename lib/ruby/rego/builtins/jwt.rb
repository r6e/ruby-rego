# frozen_string_literal: true

require_relative "base"
require_relative "base64url"
require_relative "codecs/json_decoder"
require_relative "registry"
require_relative "registry_helpers"

module Ruby
  module Rego
    module Builtins
      # JSON Web Token builtins (io.jwt.*). io.jwt.decode splits a compact JWS (header.payload.signature)
      # into [header, payload, signature]: the header and payload are the base64url-decoded JSON objects
      # and the signature is the lowercase hex of the decoded signature bytes, tracking OPA's
      # builtinJWTDecode. A token that is not exactly three base64url segments whose header and payload
      # each decode to a JSON object is undefined. Real (canonical RawURLEncoding) tokens match OPA
      # exactly; the divergences below only ever surface on hand-crafted non-canonical input.
      #
      # A token whose string is not ASCII-compatible-and-valid in its own encoding is undefined: Ruby's
      # split/Regexp#match? raise on invalid-UTF-8 bytes (ArgumentError) and on ASCII-incompatible
      # encodings like UTF-16/UTF-32 (Encoding::CompatibilityError, since they are compared against ASCII
      # literals). The guard maps both to undefined so a malformed token can never raise out of the
      # registry's totality boundary, which rescues only BuiltinArgumentError. base64url-decoded bytes
      # arrive as ASCII-8BIT, which is ascii_compatible?, so a token built from base64.decode is fine.
      #
      # Header/payload parsing goes through the same Codecs::JsonDecoder as json.unmarshal, so io.jwt.decode
      # inherits — and stays consistent with — the gem's strict JSON behaviour (RFC 8259 / Go
      # encoding/json): comments and trailing commas are rejected, number text is preserved as OPA's
      # arbitrary-precision json.Number (1.50 stays 1.50, 1e2 stays a number, large integers are exact),
      # and a \uXXXX lone surrogate yields U+FFFD — all matching OPA. A few narrow divergences remain:
      #   * Nesting: a header/payload nested deeper than depth 100 is undefined, whereas Go decodes to
      #     depth 10000. The cap is deliberate — it bounds the recursive Value.from_ruby, which otherwise
      #     overflows with an uncatchable SystemStackError around depth ~5000. Gem-stricter.
      #   * Magnitude: a number whose order of magnitude exceeds ~1e30102 is undefined (the same cap the
      #     lexer applies to literals), whereas OPA evaluates it. NOT a safe gem-stricter divergence — it
      #     bounds rational materialization (a DoS guard) at the cost of a narrowed residual fail-open
      #     above the cap, closed properly by the deferred no-materialize comparison work. Absurd scale.
      #   * Invalid UTF-8: raw invalid bytes mid-string keep their bytes rather than Go's U+FFFD
      #     replacement (the bytes round-trip; OPA's output scrubs them). Shared with json.unmarshal.
      module Jwt
        extend RegistryHelpers

        JWT_FUNCTIONS = {
          "io.jwt.decode" => { arity: 1, handler: :decode }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, JWT_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        # :reek:NilCheck -- nil is the segment-decode-failure sentinel mapped to OPA's undefined.
        def self.decode(value)
          token = string_value(value, "io.jwt.decode")
          return UndefinedValue.new unless token.encoding.ascii_compatible? && token.valid_encoding?

          parts = decode_parts(token.split(".", -1))
          parts.nil? ? UndefinedValue.new : Value.from_ruby(parts)
        end

        # [header, payload, signature_hex] when the token is exactly three segments whose header and
        # payload each base64url-decode to a JSON object and whose signature is valid base64url; nil
        # (-> undefined) otherwise. Go's builtinJWTDecode requires the object header/payload.
        # :reek:NilCheck -- nil from a sub-decode is the failure sentinel.
        def self.decode_parts(segments)
          return nil unless segments.length == 3

          decoded = [decode_object(segments[0]), decode_object(segments[1]), signature_hex(segments[2])]
          decoded.any?(&:nil?) ? nil : decoded
        end
        private_class_method :decode_parts

        # Lowercase hex of one base64url signature segment, or nil when it is not valid base64url.
        # The trailing to_s narrows unpack1's broad (Integer | Float | String | nil) RBS type to String
        # for steep; it is not dead — unpack1("H*") is always a String at runtime, but the type isn't.
        # :reek:NilCheck -- nil propagates the decode-failure sentinel.
        def self.signature_hex(segment)
          decode_segment(segment)&.unpack1("H*")&.to_s
        end
        private_class_method :signature_hex

        # The base64url segment decoded and parsed as a JSON object, or nil when it is not valid
        # base64url, not valid JSON, or not a JSON object (Go's json.Unmarshal into a map rejects the
        # latter two; OPA requires the header and payload to be objects).
        # :reek:NilCheck -- nil flows from decode_segment / a non-object parse as the failure sentinel.
        def self.decode_object(segment)
          bytes = decode_segment(segment)
          parsed = bytes && Codecs::JsonDecoder.parse(bytes)
          parsed.is_a?(Hash) ? parsed : nil
        rescue Codecs::JsonDecoder::ParseError
          nil
        end
        private_class_method :decode_object

        # The raw bytes of one base64url segment, or nil when the segment is not canonical base64url (a
        # standard-base64 '+'/'/' or non-canonical padding -> nil -> undefined). Base64Url.strict_decode
        # enforces Go's URL-safe alphabet/padding (shared with base64url.decode); see it for the
        # gem-more-strict trailing-bits divergence. The rescue is ArgumentError-only because `decode`'s
        # ascii_compatible? guard already excludes the encodings whose strict_decode match? would raise
        # Encoding::CompatibilityError — a segment of an ascii-compatible token is itself ascii-compatible.
        # :reek:NilCheck -- nil is the decode-failure sentinel.
        def self.decode_segment(segment)
          Base64Url.strict_decode(segment)
        rescue ArgumentError
          nil
        end
        private_class_method :decode_segment

        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [String]
        def self.string_value(value, context)
          Base.assert_type(value, expected: StringValue, context: context)
          value.value
        end
        private_class_method :string_value

        # Maps a builtin precondition failure to OPA's undefined. Shared by the verify and sign
        # submodules (which reopen this module); lives here so neither depends on the other's load
        # order. The registry rescues BuiltinArgumentError, so the message is internal only.
        # @return [void]
        def self.undefined!(context)
          raise BuiltinArgumentError.new(
            "Invalid #{context} input",
            expected: "valid io.jwt builtin arguments",
            actual: "invalid", context: context, location: nil
          )
        end
        private_class_method :undefined!
      end
    end
  end
end

require_relative "jwt/verify"
require_relative "jwt/sign"
require_relative "jwt/decode_verify"

Ruby::Rego::Builtins::Jwt.register!
Ruby::Rego::Builtins::Jwt.register_verifications!
Ruby::Rego::Builtins::Jwt.register_encoders!
Ruby::Rego::Builtins::Jwt.register_decode_verify!
