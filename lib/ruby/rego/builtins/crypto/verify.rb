# frozen_string_literal: true

require "openssl"

module Ruby
  module Rego
    module Builtins
      # crypto.x509.parse_and_verify_certificates(certs) and ...with_options(certs, options) — parse a
      # PEM / base64-DER certificate bundle and verify it as a chain, reproducing OPA's output:
      # json.Marshal of [verified_bool, chain], where the chain is the verified path (leaf -> root) as
      # the x509.Certificate structs parse_certificates emits, or [false, []] when verification (or
      # parsing) fails. The bundle is ordered root-first / leaf-last: certs[0] is the trusted root,
      # certs[1..-2] the intermediates, certs[-1] the leaf (Go's tls/x509 VerifyOptions layout).
      #
      # OPA rides Go's crypto/x509 Verify; this delegates path-building (signatures, validity, basic
      # constraints, name constraints, path length) to OpenSSL's verifier and layers Go's policy on top:
      # MD2/MD5/SHA-1 signatures are rejected on non-root certs (Go's InsecureAlgorithmError; the trusted
      # root is exempt), and the extended-key-usage requirement is enforced manually against Go's
      # ExtKeyUsage enum (default ServerAuth) rather than via OpenSSL purposes — OpenSSL cannot express
      # Go's any-of-multiple-usages semantics or every usage. The chain structs reuse CertificateStruct,
      # so they are byte-identical to parse_certificates. ...with_options accepts only DNSName (hostname),
      # CurrentTime (int nanoseconds), and KeyUsages ([]enum); an unknown key, wrong type, or bad enum
      # value makes the call undefined, and (an OPA marshaling quirk) its chain certs omit the injected
      # URIStrings field that the no-options builtin keeps.
      # rubocop:disable Metrics/ModuleLength
      # :reek:TooManyConstants -- the verify config (usage enum, insecure-sig pattern, option keys) is a
      # faithful port of Go's x509.VerifyOptions defaults.
      module Crypto
        VERIFY_FUNCTIONS = {
          "crypto.x509.parse_and_verify_certificates" =>
            { arity: 1, handler: :parse_and_verify_certificates },
          "crypto.x509.parse_and_verify_certificates_with_options" =>
            { arity: 2, handler: :parse_and_verify_certificates_with_options }
        }.freeze

        # Signature digests Go's x509 rejects as insecure (InsecureAlgorithmError) on non-root certs.
        INSECURE_SIGNATURE = /\b(?:md2|md5|sha1)\b/i

        # OPA's KeyUsages option enum -> Go's ExtKeyUsage integer (the value CertificateStruct emits in a
        # cert's ExtKeyUsage field). KeyUsageAny (0) drops the EKU constraint entirely.
        KEY_USAGE_ENUM = {
          "KeyUsageAny" => 0, "KeyUsageServerAuth" => 1, "KeyUsageClientAuth" => 2,
          "KeyUsageCodeSigning" => 3, "KeyUsageEmailProtection" => 4, "KeyUsageIPSECEndSystem" => 5,
          "KeyUsageIPSECTunnel" => 6, "KeyUsageIPSECUser" => 7, "KeyUsageTimeStamping" => 8,
          "KeyUsageOCSPSigning" => 9, "KeyUsageMicrosoftServerGatedCrypto" => 10,
          "KeyUsageNetscapeServerGatedCrypto" => 11, "KeyUsageMicrosoftCommercialCodeSigning" => 12,
          "KeyUsageMicrosoftKernelCodeSigning" => 13
        }.freeze
        ANY_EXT_KEY_USAGE = 0 # Go's ExtKeyUsageAny
        SERVER_AUTH_EXT_KEY_USAGE = 1 # Go's empty-KeyUsages default

        # The option keys OPA 1.17 accepts; any other key (including the doc-mentioned MaxPathLen, which
        # this OPA version does not recognize) makes the call undefined.
        VERIFY_OPTION_KEYS = %w[DNSName CurrentTime KeyUsages].freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register_verifications!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, VERIFY_FUNCTIONS)
          registry
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        def self.parse_and_verify_certificates(value)
          string = string_value(value, "crypto.x509.parse_and_verify_certificates")
          # No-options: default usage ServerAuth, and each chain cert keeps the injected URIStrings field.
          verify_result(string, { key_usages: [SERVER_AUTH_EXT_KEY_USAGE] }, uri_strings: true)
        end

        # @param value [Ruby::Rego::Value]
        # @param options_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        # :reek:NilCheck -- :invalid is the bad-options sentinel mapped to OPA's undefined.
        def self.parse_and_verify_certificates_with_options(value, options_value)
          string = string_value(value, "crypto.x509.parse_and_verify_certificates_with_options")
          opts = verify_options(options_value)
          return UndefinedValue.new unless opts.is_a?(Hash)

          # ...with_options marshals each chain cert as Go's raw x509.Certificate — WITHOUT the URIStrings
          # field parse_certificates injects (an OPA quirk: the two builtins differ here).
          verify_result(string, opts, uri_strings: false)
        end

        # [verified, chain] as a Value: [true, chain-of-structs] on a verified chain, else [false, []].
        # A builder/verify failure maps to [false, []] (totality) rather than aborting — the structural
        # exceptions are fully qualified since Ruby::Rego::TypeError shadows ::TypeError here.
        # :reek:NilCheck :reek:BooleanParameter -- nil = "did not verify"; uri_strings is the field switch.
        # :reek:TooManyStatements -- the verify -> build -> EKU-check -> wrap sequence reads clearest inline.
        def self.verify_result(string, opts, uri_strings:)
          chain = verified_chain(string, opts)
          return unverified if chain.nil?

          structs = chain.map { |cert| CertificateStruct.build(cert) }
          return unverified unless key_usage_satisfied?(structs, opts[:key_usages])

          Value.from_ruby([true, chain_output(structs, uri_strings)])
        rescue OpenSSL::OpenSSLError, MalformedCertificate, SystemStackError,
               ::NoMethodError, ::TypeError, ::IndexError, ::ArgumentError, ::RangeError
          unverified
        end
        private_class_method :verify_result

        # OPA's verification-failed result, [false, []].
        def self.unverified
          empty = [] # : Array[untyped]
          Value.from_ruby([false, empty])
        end
        private_class_method :unverified

        # The chain structs as emitted: the no-options builtin keeps URIStrings, ...with_options drops it
        # (Go's raw x509.Certificate has no such field).
        # :reek:ControlParameter -- uri_strings selects the documented per-builtin field difference.
        def self.chain_output(structs, uri_strings)
          return structs if uri_strings

          structs.map { |struct| struct.except("URIStrings") }
        end
        private_class_method :chain_output

        # The verified chain (leaf -> root) as OpenSSL certs, or nil when the bundle does not parse, has
        # fewer than two certs, carries an insecure (MD2/MD5/SHA-1) non-root signature, or fails OpenSSL
        # path validation or the DNSName hostname check. EKU is checked separately (key_usage_satisfied?).
        # certs[0] is the trusted root and certs[-1] the leaf.
        # :reek:NilCheck :reek:TooManyStatements -- a sequence of verification gates, each returning nil.
        # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
        def self.verified_chain(string, opts)
          certs = certificates_from(string)
          return nil if certs.nil? || certs.length < 2 || insecure_chain?(certs)

          store = OpenSSL::X509::Store.new
          store.add_cert(certs.first)
          time = opts[:time]
          store.time = time if time
          leaf = certs.last
          return nil unless store.verify(leaf, certs[1...-1] || [])

          dns_name = opts[:dns_name]
          return nil if dns_name && !OpenSSL::SSL.verify_certificate_identity(leaf, dns_name)

          store.chain
        rescue OpenSSL::OpenSSLError
          nil
        end
        private_class_method :verified_chain
        # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity

        # Whether any NON-root cert carries an MD2/MD5/SHA-1 signature (Go's InsecureAlgorithmError; the
        # trusted root at certs[0] is exempt, as Go does not check the trust anchor's own signature).
        def self.insecure_chain?(certs)
          certs.drop(1).any? { |cert| INSECURE_SIGNATURE.match?(cert.signature_algorithm) }
        end
        private_class_method :insecure_chain?

        # Go's checkChainForKeyUsage: a chain satisfies the requested usages if ANY requested usage is
        # acceptable across EVERY cert (a cert with no EKU extension permits anything; otherwise it must
        # list the usage or anyExtendedKeyUsage). KeyUsageAny in the request short-circuits to true.
        # :reek:NestedIterators -- any-required-usage over all-chain-certs is the clearest form.
        def self.key_usage_satisfied?(chain, required)
          return true if required.include?(ANY_EXT_KEY_USAGE)

          required.any? { |usage| chain.all? { |struct| usage_permitted?(struct, usage) } }
        end
        private_class_method :key_usage_satisfied?

        # Whether one chain cert permits a usage: a cert with neither a known nor an unknown EKU has no
        # restriction; otherwise its ExtKeyUsage must include the usage or anyExtendedKeyUsage.
        # :reek:NilCheck -- a nil ExtKeyUsage/UnknownExtKeyUsage field is Go's "no usages" (empty slice).
        def self.usage_permitted?(struct, usage)
          known = struct["ExtKeyUsage"] || []
          return true if known.empty? && (struct["UnknownExtKeyUsage"] || []).empty?

          known.include?(usage) || known.include?(ANY_EXT_KEY_USAGE)
        end
        private_class_method :usage_permitted?

        # Parse the options object into {key_usages, time, dns_name}, or :invalid for an unrecognized key,
        # a wrong-typed value, or a bad KeyUsages enum (all -> OPA undefined). Mirrors OPA's strict decode
        # of the options into Go's VerifyOptions.
        # :reek:TooManyStatements -- the per-key validation reads clearest inline.
        # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
        def self.verify_options(options_value)
          return :invalid unless options_value.is_a?(ObjectValue)

          options = options_value.to_ruby
          return :invalid unless options.keys.all? { |key| VERIFY_OPTION_KEYS.include?(key) }

          opts = { key_usages: [SERVER_AUTH_EXT_KEY_USAGE] } # : Hash[Symbol, untyped]
          if options.key?("DNSName")
            dns_name = options["DNSName"]
            return :invalid unless dns_name.is_a?(String)

            opts[:dns_name] = dns_name
          end
          if options.key?("CurrentTime")
            nanos = options["CurrentTime"]
            return :invalid unless nanos.is_a?(Integer)

            opts[:time] = Time.at(nanos / 1_000_000_000.0)
          end
          if options.key?("KeyUsages")
            usages = key_usage_enums(options["KeyUsages"])
            return :invalid if usages == :invalid

            opts[:key_usages] = usages
          end
          opts
        end
        private_class_method :verify_options
        # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity

        # The requested KeyUsages list as Go ExtKeyUsage integers, or :invalid for a non-list / non-string
        # member / unknown enum. An empty list is Go's default (ServerAuth).
        # :reek:TooManyStatements -- the list / member / enum validation guards read clearest inline.
        def self.key_usage_enums(usages)
          return :invalid unless usages.is_a?(Array) && usages.all?(String)
          return [SERVER_AUTH_EXT_KEY_USAGE] if usages.empty?
          return :invalid unless usages.all? { |usage| KEY_USAGE_ENUM.key?(usage) }

          usages.map { |usage| KEY_USAGE_ENUM.fetch(usage) }
        end
        private_class_method :key_usage_enums
      end
      # rubocop:enable Metrics/ModuleLength
    end
  end
end

require_relative "certificate_struct"

Ruby::Rego::Builtins::Crypto.register_verifications!
