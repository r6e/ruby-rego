# frozen_string_literal: true

require "json"
require_relative "base"
require_relative "base64url"
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
      # Header/payload parsing goes through the same JSON.parse as json.unmarshal, so io.jwt.decode
      # inherits — and stays consistent with — the gem's JSON behaviour. The gem-wide divergences from
      # OPA (Go encoding/json) that follow are shared with json.unmarshal and are not closed here (the
      # fix belongs in a gem-wide JSON layer; a JWT-only reimplementation would diverge from
      # json.unmarshal). The first two are in the safe, gem-stricter direction:
      #   * Nesting: a header/payload nested deeper than JSON.parse's default (max_nesting: 100) is
      #     undefined, whereas Go decodes to depth 10000. The default is deliberately kept — raising it to
      #     Go's limit makes the recursive Value.from_ruby overflow with an uncatchable SystemStackError
      #     around depth ~5000, which would abort policy evaluation.
      #   * Invalid UTF-8 in a JSON string value: raw invalid bytes keep their bytes (Go replaces with
      #     U+FFFD) and a \uXXXX lone surrogate is undefined (Go yields U+FFFD).
      # The remaining two predate this builtin (json.unmarshal already behaves identically) and are not
      # in the stricter direction:
      #   * Comments: Ruby's json accepts // and /* */ comments unconditionally (no disable flag); Go
      #     rejects them, so a commented header/payload decodes here but is undefined in OPA.
      #   * Number precision: JSON numbers become Ruby Integer/Float, so high-precision decimals and
      #     exponent forms (1e2 -> 100.0) lose OPA's arbitrary-precision json.Number fidelity. Integers
      #     are exact (Ruby Bignum).
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
          parsed = bytes && JSON.parse(bytes)
          parsed.is_a?(Hash) ? parsed : nil
        rescue JSON::ParserError
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

Ruby::Rego::Builtins::Jwt.register!
Ruby::Rego::Builtins::Jwt.register_verifications!
Ruby::Rego::Builtins::Jwt.register_encoders!
