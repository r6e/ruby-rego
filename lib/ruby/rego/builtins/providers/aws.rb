# frozen_string_literal: true

require "openssl"
require_relative "../base"
require_relative "../registry"
require_relative "../registry_helpers"
require_relative "../codecs"
require_relative "../uri/parser"

module Ruby
  module Rego
    module Builtins
      module Providers
        # providers.aws.sign_req(request, aws_config, time_ns): sign an HTTP request with AWS Signature
        # Version 4, matching OPA's topdown builtinAWSSigV4SignReq (internal/providers/aws/signing_v4.go).
        # Deterministic: the signing time is the time_ns argument, not a clock. Returns the request copied
        # with its `headers` replaced by the original (single-valued) headers plus the signing headers
        # (Authorization, host, x-amz-date, and conditionally x-amz-content-sha256 / x-amz-security-token).
        #
        # OPA's SigV4 deviates from the AWS spec in three byte-affecting ways the port reproduces: the
        # canonical query is RawQuery VERBATIM (not sorted/re-encoded); header values are signed verbatim
        # (not trimmed); and the canonical URI is url.EscapedPath() (user %-encoding preserved, never
        # double-encoded). The body is hashed as raw_body (string, wins over body) or json.Marshal(body)
        # (reusing Codecs.canonical_json — sorted keys + Go HTML escaping), so the body number model is the
        # gem-wide json.marshal one (Float#to_s); real callers pass raw_body, sidestepping it.
        #
        # Two documented divergences, both on inputs real callers don't hit: (1) two request headers whose
        # names differ ONLY in case (e.g. "X-Foo" and "x-foo") — OPA's signature is nondeterministic there
        # (Go map iteration order decides which lowercased value wins), so the gem's deterministic choice
        # matches only one of OPA's branches; (2) an invalid-UTF-8 url or header key — the gem returns
        # undefined (like uri.parse) rather than signing, to stay total.
        #
        # Any precondition failure is undefined (the registry maps BuiltinArgumentError -> undefined):
        # a non-object request/config; a request key outside http.send's allowed set or a missing/non-string
        # method/url; an unparseable url; an aws_config missing one of the four required string keys (empty
        # strings are accepted) or holding a non-string for one; a non-integer / int64-overflowing time_ns;
        # or a non-boolean disable_payload_signing.
        # rubocop:disable Metrics/ModuleLength -- a faithful step-by-step port of OPA's SigV4 signer.
        module Aws
          extend RegistryHelpers

          AWS_FUNCTIONS = {
            "providers.aws.sign_req" => { arity: 3, handler: :sign_req }
          }.freeze

          CONTEXT = "providers.aws.sign_req"
          # aws_config keys that must be present and string-typed (empty strings allowed).
          REQUIRED_CONFIG = %w[aws_access_key aws_secret_access_key aws_service aws_region].freeze
          # The http.send request keys OPA's validateHTTPRequestOperand accepts; any other key is an error.
          ALLOWED_REQUEST_KEYS = %w[
            method url body enable_redirect force_json_decode force_yaml_decode headers raw_body timeout
            tls_use_system_certs tls_ca_cert tls_ca_cert_file tls_ca_cert_env_variable tls_client_cert
            tls_client_cert_file tls_client_cert_env_variable tls_client_key tls_client_key_file
            tls_client_key_env_variable tls_server_name tls_insecure_skip_verify cache force_cache
            force_cache_duration_seconds raise_error caching_mode max_retry_attempts cache_ignored_headers
          ].freeze
          # Headers excluded from signing regardless of the request (awsSigv4IgnoredHeaders), lowercased.
          IGNORED_HEADERS = %w[authorization user-agent x-amzn-trace-id].freeze
          # Services for which OPA emits the x-amz-content-sha256 header (string-equal, case-sensitive).
          PAYLOAD_HASH_SERVICES = %w[s3 glacier].freeze

          ALGORITHM = "AWS4-HMAC-SHA256"
          AMZ_DATE_FORMAT = "%Y%m%dT%H%M%SZ"
          DATE_FORMAT = "%Y%m%d"
          INT64_MIN = -(2**63)
          INT64_MAX = (2**63) - 1

          # @return [Ruby::Rego::Builtins::BuiltinRegistry]
          def self.register!
            registry = BuiltinRegistry.instance
            register_configured_functions(registry, AWS_FUNCTIONS)
            registry
          end

          private_class_method :register_configured_functions, :register_configured_function

          # @param request_value [Ruby::Rego::Value]
          # @param config_value [Ruby::Rego::Value]
          # @param time_ns_value [Ruby::Rego::Value]
          # @return [Ruby::Rego::Value] the signed request object, or undefined
          def self.sign_req(request_value, config_value, time_ns_value)
            request = object_or_undefined(request_value)
            config = object_or_undefined(config_value)
            time = signing_time(time_ns_value)
            validate_request_keys!(request)
            creds = credentials(config)
            signed_headers = sign(request, creds, time)

            output_request(request, signed_headers)
          end

          # --- operand validation -------------------------------------------------------------------

          # :reek:NilCheck
          def self.object_or_undefined(value)
            ruby = value.to_ruby
            undefined! unless ruby.is_a?(Hash)
            ruby
          end

          # time.Unix(0, ns).UTC() — ns must be an integer within int64 (ast.Number.Int64()).
          # :reek:NilCheck
          def self.signing_time(value)
            ns = value.to_ruby
            undefined! unless ns.is_a?(Integer) && ns.between?(INT64_MIN, INT64_MAX)

            Time.at(0, ns, :nanosecond).utc
          end

          def self.validate_request_keys!(request)
            undefined! unless (request.keys - ALLOWED_REQUEST_KEYS).empty?
            undefined! unless request.key?("method") && request.key?("url")
          end

          # The four required string config values, the optional session token (non-string -> ""), and the
          # optional disable_payload_signing flag (present but non-boolean -> undefined).
          # :reek:NilCheck
          def self.credentials(config)
            REQUIRED_CONFIG.each { |key| undefined! unless config[key].is_a?(String) }
            token = config["aws_session_token"]
            {
              access_key: config["aws_access_key"], secret_key: config["aws_secret_access_key"],
              service: config["aws_service"], region: config["aws_region"],
              session_token: token.is_a?(String) ? token : "",
              disable_payload_signing: disable_payload_signing?(config)
            }
          end

          # :reek:NilCheck
          def self.disable_payload_signing?(config)
            return false unless config.key?("disable_payload_signing")

            flag = config["disable_payload_signing"]
            undefined! unless [true, false].include?(flag)
            flag
          end

          # --- signing ------------------------------------------------------------------------------

          # Builds the SigV4 signing headers and returns the output headers object (original headers with
          # their casing, restored, plus Authorization and the aws signing headers).
          # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
          def self.sign(request, creds, time)
            method, components = request_target(request)
            amz_date = time.strftime(AMZ_DATE_FORMAT)
            scope_date = time.strftime(DATE_FORMAT)
            content_hash = content_hash(request, creds[:disable_payload_signing])

            aws_headers = aws_headers(components.host, amz_date, content_hash, creds)
            request_headers = header_map(request)
            canonical_headers = canonical_headers(request_headers, aws_headers)
            signed_list = canonical_headers.keys.join(";")

            canonical_request = canonical_request(method, components, canonical_headers, signed_list, content_hash)
            signature = signature(canonical_request, creds, amz_date, scope_date)
            authorization = authorization(signature, signed_list, creds, scope_date)

            output_headers(request_headers, aws_headers, authorization)
          end
          # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

          # method (string) + parsed url Components. Both method and url must be strings; url must parse.
          # :reek:NilCheck
          def self.request_target(request)
            method = request["method"]
            url = request["url"]
            undefined! unless method.is_a?(String) && url.is_a?(String) && encodable?(url)

            components = Uri::Parser.parse(url)
            undefined! if components.nil?
            [method, components]
          end

          # Total-safety guard, matching uri.parse: an invalid-UTF-8 (or non-ASCII-compatible) string makes
          # the parser and String#downcase raise a bare ArgumentError, which would escape the registry's
          # BuiltinArgumentError rescue and abort the whole policy. A BINARY string (e.g. from base64.decode)
          # is ASCII-compatible and valid, so it still signs. DIVERGENCE: OPA signs an invalid-UTF-8 url /
          # header key; the gem returns undefined (the same accepted divergence uri.parse documents).
          def self.encodable?(string)
            Base.byte_safe_encoding?(string)
          end

          # x-amz-content-sha256 payload value: UNSIGNED-PAYLOAD when disable_payload_signing, else
          # hex(sha256(body)). Body is raw_body (string; wins) or json.Marshal(body) or "".
          # :reek:ControlParameter -- branches on the flag, mirroring Go's getContentHash.
          def self.content_hash(request, disable_payload_signing)
            return "UNSIGNED-PAYLOAD" if disable_payload_signing

            OpenSSL::Digest::SHA256.hexdigest(body_bytes(request))
          end

          # raw_body wins over body (matching getReqBodyBytes); a non-string raw_body is "". A non-
          # marshalable `body` (non-finite number, over-deep) makes canonical_json raise
          # BuiltinArgumentError, which the registry maps to undefined — the intended precondition outcome.
          # :reek:NilCheck
          def self.body_bytes(request)
            if request.key?("raw_body")
              raw = request["raw_body"]
              raw.is_a?(String) ? raw : ""
            elsif request.key?("body")
              Codecs.canonical_json(Value.from_ruby(request["body"]))
            else
              ""
            end
          end

          # The aws-added signing headers, all lowercase (x-amz-content-sha256 only for s3/glacier;
          # x-amz-security-token only with a session token). Insertion order is the emission order.
          def self.aws_headers(host, amz_date, content_hash, creds)
            token = creds[:session_token]
            headers = { "host" => host.to_s, "x-amz-date" => amz_date }
            headers["x-amz-content-sha256"] = content_hash if PAYLOAD_HASH_SERVICES.include?(creds[:service])
            headers["x-amz-security-token"] = token unless token.empty?
            headers
          end

          # The request's headers object as { original_key => value }; undefined if a present `headers` is
          # not an object. OPA's objectToMap keeps only string values verbatim — a non-string value (array,
          # number, ...) becomes a single empty string, both for signing and the restored output header.
          # :reek:NilCheck
          def self.header_map(request)
            headers = request["headers"]
            return {} unless request.key?("headers")

            undefined! unless headers.is_a?(Hash)
            headers.to_h do |key, value|
              name = key.to_s
              undefined! unless encodable?(name) # lowercased during signing -> would raise on invalid UTF-8
              [name, value.is_a?(String) ? value : ""]
            end
          end

          # The headers to sign: aws headers, then every request header whose lowercased name is not
          # ignored (keyed by lowercased name), so a user header overrides the aws value on collision
          # (e.g. a user "Host" is signed in place of url.Host). Sorted by key. Keys and values are forced
          # to ASCII-8BIT (.b): SigV4 signs BYTES (like Go), and joining two attacker strings of
          # INCOMPATIBLE Ruby encodings (e.g. a UTF-8 and an ASCII-8BIT header) would otherwise raise
          # Encoding::CompatibilityError, which escapes the registry's rescue and aborts the policy.
          # :reek:DuplicateMethodCall -- value.b in both the aws and request passes are distinct calls.
          def self.canonical_headers(request_headers, aws_headers)
            signed = aws_headers.to_h { |key, value| [key.b, value.b] }
            request_headers.each do |key, value|
              lower = key.downcase
              signed[lower.b] = value.b unless IGNORED_HEADERS.include?(lower)
            end
            signed.sort.to_h
          end

          # method\nEscapedPath\nRawQuery\n<k:v\n...>\n<signed;list>\n<payload-hash>. Each piece is forced
          # to ASCII-8BIT (.b) so the byte concatenation can't raise on mixed-encoding inputs (see
          # canonical_headers); the canonical_headers/signed_list pieces are already byte strings.
          def self.canonical_request(method, components, canonical_headers, signed_list, content_hash)
            header_lines = canonical_headers.map { |key, value| "#{key}:#{value}\n" }.join
            [
              method.b, Uri::Parser.escaped_path(components).b, components.raw_query.to_s.b,
              "#{header_lines}\n#{signed_list}", content_hash.b
            ].join("\n")
          end

          # hex(HMAC(kSigning, stringToSign)) with the date-scoped key derivation. region/service forced to
          # bytes so the scope concatenation can't raise on mixed-encoding config values.
          def self.signature(canonical_request, creds, amz_date, scope_date)
            scope = "#{scope_date}/#{creds[:region].b}/#{creds[:service].b}/aws4_request"
            string_to_sign = [
              ALGORITHM, amz_date, scope, OpenSSL::Digest::SHA256.hexdigest(canonical_request)
            ].join("\n")
            OpenSSL::HMAC.hexdigest("SHA256", signing_key(creds, scope_date), string_to_sign)
          end

          # region/service aren't byte-forced here (unlike in signature/authorization): they're HMAC DATA
          # arguments, not Ruby string concatenations, so they can't raise Encoding::CompatibilityError.
          def self.signing_key(creds, scope_date)
            key = OpenSSL::HMAC.digest("SHA256", "AWS4#{creds[:secret_key].b}", scope_date)
            key = OpenSSL::HMAC.digest("SHA256", key, creds[:region])
            key = OpenSSL::HMAC.digest("SHA256", key, creds[:service])
            OpenSSL::HMAC.digest("SHA256", key, "aws4_request")
          end

          # The Authorization header. The credential pieces are byte-forced (mixed-encoding safety); the
          # result is re-tagged UTF-8 when valid so a normal (ASCII/UTF-8) Authorization matches OPA's
          # string, falling back to the raw bytes only for the pathological non-UTF-8-signed-name case.
          def self.authorization(signature, signed_list, creds, scope_date)
            credential = "#{creds[:access_key].b}/#{scope_date}/#{creds[:region].b}/#{creds[:service].b}/aws4_request"
            auth = "#{ALGORITHM} Credential=#{credential},SignedHeaders=#{signed_list},Signature=#{signature}"
            tagged = auth.dup.force_encoding(Encoding::UTF_8)
            tagged.valid_encoding? ? tagged : auth
          end

          # --- output -------------------------------------------------------------------------------

          # Original headers restored with their casing, then Authorization, then the aws headers
          # (lowercase). Later inserts win on an exact-string key collision (so the aws lowercase `host`
          # overrides a user lowercase `host`, while a user `Host` coexists as a distinct key).
          def self.output_headers(request_headers, aws_headers, authorization)
            out = request_headers.dup
            out["Authorization"] = authorization
            out.merge(aws_headers)
          end

          # reqObj.Copy() with headers replaced. `request` is the already-converted hash from sign_req;
          # merge is non-mutating, so it is not disturbed (and we avoid re-running to_ruby on the value).
          def self.output_request(request, signed_headers)
            Value.from_ruby(request.merge("headers" => signed_headers))
          end

          # @return [void]
          def self.undefined!
            raise BuiltinArgumentError.new(
              "Invalid #{CONTEXT} input", expected: "valid #{CONTEXT} arguments",
                                          actual: "invalid", context: CONTEXT, location: nil
            )
          end

          private_class_method :object_or_undefined, :signing_time, :validate_request_keys!,
                               :credentials, :disable_payload_signing?, :sign, :request_target, :encodable?,
                               :content_hash, :body_bytes, :aws_headers, :header_map, :canonical_headers,
                               :canonical_request, :signature, :signing_key, :authorization,
                               :output_headers, :output_request, :undefined!
        end
        # rubocop:enable Metrics/ModuleLength
      end
    end
  end
end

Ruby::Rego::Builtins::Providers::Aws.register!
