# frozen_string_literal: true

require "json"
require_relative "verify"
require_relative "sign"

# rubocop:disable Metrics/ModuleLength
module Ruby
  module Rego
    module Builtins
      # io.jwt.decode_verify(jwt, constraints): verify a compact JWS against a key AND a set of standard
      # claim constraints, returning [valid, header, payload] (mirroring OPA's builtinJWTDecodeVerify).
      # `valid` is true only when the signature verifies and every applicable constraint holds; otherwise
      # the result is [false, {}, {}]. The outcome is THREE-way, like verify_*:
      #   * undefined — the constraints object or the token is structurally unusable: a token that is not
      #     three base64url segments whose header/payload are JSON objects and whose signature is base64url
      #     (a payload `exp`/`nbf` that is not a number is also undefined); a constraints value that is not
      #     an object, carries an unknown key, lacks exactly one of `secret`/`cert`, has a non-string
      #     `secret`/`cert`/`alg`/`iss`/`aud`, an empty or unparseable `cert`, or a `time` that is not a
      #     number >= 0.
      #   * [false, {}, {}] — the token and constraints are well-formed but a check fails: signature does
      #     not verify, the header `alg` is unsupported/"none" or does not match a constraint `alg`, the
      #     scheme's key is absent (HMAC needs `secret`, asymmetric needs `cert`), `exp`/`nbf`/`iss`/`aud`
      #     do not hold.
      #   * [true, header, payload] — verified and all constraints satisfied.
      # `exp`/`nbf` are seconds (JWT NumericDate); the `time` constraint is nanoseconds (default: now), and
      # OPA compares time_ns against the claim * 1e9 — valid while time < exp*1e9 and time >= nbf*1e9. An
      # `aud` claim requires a matching `aud` constraint and vice versa (a string `aud` matches by equality,
      # an array `aud` by membership). The signature path reuses verify_*'s scheme machinery keyed by the
      # header `alg` (JWS_ALGORITHMS), and the token/key parsing reuses io.jwt.decode / Jwt::Jwk.
      #
      # Divergence (upstream bug, see opa-builtin-upstream-bugs): OPA panics on a non-string `iss` claim
      # (number or boolean) when an `iss` constraint is given (ast type assertion vs ast.String); the gem
      # stays total and returns false (a non-string iss never equals a string constraint).
      module Jwt
        DECODE_VERIFY_FUNCTIONS = {
          "io.jwt.decode_verify" => { arity: 2, handler: :decode_verify }
        }.freeze

        DECODE_VERIFY_CONTEXT = "io.jwt.decode_verify"
        # The closed set of constraint keys OPA accepts; any other key makes the constraints undefined.
        CONSTRAINT_KEYS = %w[cert secret alg iss aud time].freeze
        NS_PER_SECOND = 1_000_000_000

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register_decode_verify!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, DECODE_VERIFY_FUNCTIONS)
          registry
        end

        # @param jwt_value [Ruby::Rego::Value] the compact JWS string
        # @param constraints_value [Ruby::Rego::Value] the constraints object
        # @return [Ruby::Rego::Value] [valid, header, payload], or undefined
        # :reek:NilCheck
        def self.decode_verify(jwt_value, constraints_value)
          constraints = parse_constraints(constraints_value)
          token = parse_token(string_value(jwt_value, DECODE_VERIFY_CONTEXT))
          undefined!(DECODE_VERIFY_CONTEXT) if constraints.nil? || token.nil?

          verified?(constraints, token) ? verified_result(token) : invalid_result
        end

        # The validated constraints as a symbol-keyed Hash, or nil (-> undefined) when the object is not a
        # usable constraints set. An empty-string alg/iss/aud is normalised to nil — OPA treats it as the
        # Go zero value (unset), the same as an absent field.
        def self.parse_constraints(constraints_value)
          obj = constraints_value.to_ruby
          return nil unless valid_constraints?(obj)

          { secret: obj["secret"], cert: obj["cert"], alg: optional_string(obj["alg"]),
            iss: optional_string(obj["iss"]), aud: optional_string(obj["aud"]), time: obj["time"] }
        end
        private_class_method :parse_constraints

        # A present, non-empty string, or nil (an absent or empty optional constraint — OPA's unset).
        # :reek:NilCheck
        def self.optional_string(value)
          value unless value.nil? || value.empty?
        end
        private_class_method :optional_string

        # The constraints object is a Hash with only known keys, exactly one of secret/cert, and well-typed
        # fields. cert is parsed eagerly (an unparseable cert is undefined even for an HMAC token).
        def self.valid_constraints?(obj)
          obj.is_a?(Hash) && (obj.keys - CONSTRAINT_KEYS).empty? &&
            (obj.key?("cert") ^ obj.key?("secret")) &&
            valid_key_field?(obj) && valid_string_fields?(obj) && valid_time?(obj)
        end
        private_class_method :valid_constraints?

        # The present one of secret/cert is a non-empty string; a cert must additionally parse into a usable
        # key via verify_*'s public_keys (PEM cert/SPKI or JWK/JWK Set) — nil = unparseable -> undefined,
        # even for an HMAC token, matching OPA's eager getKeyFromCertOrJWK.
        # :reek:NilCheck
        def self.valid_key_field?(obj)
          if obj.key?("cert")
            cert = obj["cert"]
            cert.is_a?(String) && !cert.empty? && !public_keys(cert).nil?
          else
            secret = obj["secret"]
            secret.is_a?(String) && !secret.empty?
          end
        end
        private_class_method :valid_key_field?

        # alg/iss/aud, when present, must each be a string (an array or number aud is undefined, even
        # though a token's aud claim may be an array).
        def self.valid_string_fields?(obj)
          %w[alg iss aud].all? { |field| !obj.key?(field) || obj[field].is_a?(String) }
        end
        private_class_method :valid_string_fields?

        # time, when present, must be a number >= 0 (OPA's -1 "unset" sentinel and other negatives are
        # undefined; floats and 0 are accepted).
        def self.valid_time?(obj)
          return true unless obj.key?("time")

          time = obj["time"]
          # The Complex guard is load-bearing, not redundant: Complex is a Numeric but `Complex >= 0`
          # raises NoMethodError (no Comparable), which would escape the registry's totality boundary.
          time.is_a?(Numeric) && !time.is_a?(Complex) && time >= 0
        end
        private_class_method :valid_time?

        # The parsed token as { header, payload, signing_input, signature_segment }, or nil (-> undefined)
        # when it is not three segments whose header and payload are JSON objects. A payload exp/nbf that is
        # present but not a number is undefined too (OPA cannot compare it). The signature is NOT decoded
        # here: OPA decodes it only once the header names an alg, so a non-base64url signature is undefined
        # only then (and false when the header has no alg) — see verified?.
        # :reek:NilCheck :reek:TooManyStatements
        def self.parse_token(jwt)
          parts = three_segments(jwt)
          return nil if parts.nil?

          header_seg = parts.fetch(0)
          payload_seg = parts.fetch(1)
          header = decode_object(header_seg)
          payload = decode_object(payload_seg)
          return nil if header.nil? || payload.nil? || !numeric_dates?(payload)

          { header: header, payload: payload,
            signing_input: "#{header_seg}.#{payload_seg}", signature_segment: parts.fetch(2) }
        end
        private_class_method :parse_token

        # exp/nbf, when present in the payload, must be numbers.
        def self.numeric_dates?(payload)
          %w[exp nbf].all? { |claim| !payload.key?(claim) || payload[claim].is_a?(Numeric) }
        end
        private_class_method :numeric_dates?

        # True when the signature verifies and every applicable constraint (alg, exp, nbf, iss, aud) holds.
        # :reek:NilCheck :reek:TooManyStatements
        def self.verified?(constraints, token)
          signature = signature_for(constraints, token)
          return false if signature.nil?

          payload = token[:payload]
          config = JWS_ALGORITHMS[token[:header]["alg"]]
          return false if config.nil?

          signature_ok?(config, constraints, [token[:signing_input], signature]) &&
            time_ok?(payload, constraints) && iss_ok?(payload, constraints) && aud_ok?(payload, constraints)
        end
        private_class_method :verified?

        # The decoded signature bytes to verify, or nil for a pre-check failure (-> false): the header has
        # no `alg` key, or an `alg` constraint does not match the header. A header whose `alg` is present
        # but not a string is undefined (OPA's header type assertion). Once the header names a string alg,
        # the signature is decoded and a non-base64url signature is undefined (matching OPA, which decodes
        # it only at that point); an empty signature decodes to "" and verifies as false.
        # :reek:NilCheck :reek:TooManyStatements :reek:DuplicateMethodCall
        def self.signature_for(constraints, token)
          header = token[:header]
          return nil unless header.key?("alg")

          alg = header["alg"]
          undefined!(DECODE_VERIFY_CONTEXT) unless alg.is_a?(String)
          expected_alg = constraints[:alg]
          return nil if expected_alg && expected_alg != alg

          signature = decode_segment(token[:signature_segment])
          undefined!(DECODE_VERIFY_CONTEXT) if signature.nil?

          signature
        end
        private_class_method :signature_for

        # The header alg's scheme picks the key: HMAC verifies against `secret`, the asymmetric schemes
        # against `cert`. The wrong-scheme key being absent is a normal failure (false), not undefined.
        # :reek:NilCheck
        def self.signature_ok?(config, constraints, signed)
          key = config[:scheme] == :hmac ? constraints[:secret] : constraints[:cert]
          return false if key.nil?

          scheme_result(config, key, signed) == true
        end
        private_class_method :signature_ok?

        # exp: valid while time < exp*1e9; nbf: valid while time >= nbf*1e9 (time defaults to now in ns).
        def self.time_ok?(payload, constraints)
          now = constraints[:time] || current_time_ns
          (!payload.key?("exp") || now < payload["exp"] * NS_PER_SECOND) &&
            (!payload.key?("nbf") || now >= payload["nbf"] * NS_PER_SECOND)
        end
        private_class_method :time_ok?

        # An iss constraint, when given, must equal the payload iss.
        # :reek:NilCheck
        def self.iss_ok?(payload, constraints)
          iss = constraints[:iss]
          iss.nil? || payload["iss"] == iss
        end
        private_class_method :iss_ok?

        # aud follows OPA's validAudience against the constraint (nil = the unset/"" zero value): a token
        # WITHOUT an aud claim is valid only when the constraint is unset; a token WITH an aud must match
        # the constraint (which is "" when unset) — a string aud by equality, an array aud by membership.
        # :reek:NilCheck
        def self.aud_ok?(payload, constraints)
          con_aud = constraints[:aud]
          return con_aud.nil? unless payload.key?("aud")

          aud_matches?(payload["aud"], con_aud || "")
        end
        private_class_method :aud_ok?

        def self.aud_matches?(token_aud, con_aud)
          case token_aud
          when String then token_aud == con_aud
          when Array then token_aud.include?(con_aud)
          else false
          end
        end
        private_class_method :aud_matches?

        # Now in nanoseconds since the epoch (OPA's default `time`, time.Now().UnixNano()). The default-time
        # path is non-deterministic; goldens/specs that exercise exp/nbf pass an explicit `time`.
        def self.current_time_ns
          Process.clock_gettime(Process::CLOCK_REALTIME, :nanosecond)
        end
        private_class_method :current_time_ns

        # @return [Ruby::Rego::Value] [true, header, payload]
        def self.verified_result(token)
          Value.from_ruby([true, token[:header], token[:payload]])
        end
        private_class_method :verified_result

        # @return [Ruby::Rego::Value] [false, {}, {}] — OPA's invalid-token shape.
        def self.invalid_result
          empty = {} # : Hash[String, untyped]
          Value.from_ruby([false, empty, empty])
        end
        private_class_method :invalid_result
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength
