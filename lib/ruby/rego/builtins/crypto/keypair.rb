# frozen_string_literal: true

require "base64"
require "openssl"

module Ruby
  module Rego
    module Builtins
      # crypto.x509.parse_keypair(cert, key) — parse a PEM / base64-DER certificate (chain) together
      # with its matching PEM / base64-DER private key into the JSON shape OPA emits: json.Marshal of
      # Go's tls.Certificate. Leaf is the same x509.Certificate struct parse_certificates builds, minus
      # the injected URIStrings field (tls.Certificate.Leaf is Go's raw x509.Certificate, which has no
      # URIStrings); Certificate is the raw DER of each cert in the chain; PrivateKey reuses the Go
      # private-key rendering parse_private_keys already produces; and OCSPStaple /
      # SignedCertificateTimestamps / SupportedSignatureAlgorithms are always null. The private key must
      # match the leaf certificate's public key (Go's tls.X509KeyPair validates this) — a mismatched,
      # missing, encrypted, public-only, or unsupported key makes the call undefined. Reopens Crypto to
      # share the certificate chain parser, the key reader, and the Go private-key struct renderer.
      module Crypto
        KEYPAIR_FUNCTIONS = {
          "crypto.x509.parse_keypair" => { arity: 2, handler: :parse_keypair }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register_keypairs!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, KEYPAIR_FUNCTIONS)
          registry
        end

        # @param cert_value [Ruby::Rego::Value]
        # @param key_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        # :reek:NilCheck -- nil is the parse-failure sentinel from certificates_from / matching_key.
        # :reek:TooManyStatements -- a faithful port of OPA's keypair parse + validation flow.
        def self.parse_keypair(cert_value, key_value)
          cert_string = string_value(cert_value, "crypto.x509.parse_keypair")
          key_string = string_value(key_value, "crypto.x509.parse_keypair")
          return UndefinedValue.new unless scannable?(cert_string) && scannable?(key_string)

          certs = keypair_certs(cert_string)
          return UndefinedValue.new if certs.nil?

          key = matching_key(certs.first, key_string)
          return UndefinedValue.new if key.nil?

          build_keypair_struct(certs, key)
        end

        # The certificate chain, the way Go's tls.X509KeyPair reads it — NOT parse_certificates' dual
        # dispatch. A PEM input contributes every CERTIFICATE block and silently ignores the rest (a key
        # block, comments); at least one CERTIFICATE is required. A non-PEM input is ONE base64-DER
        # certificate (Go x509.ParseCertificate rejects trailing bytes — OpenSSL tolerates them, so the
        # length is checked); base64-of-PEM is decoded by pem_blocks then scanned as PEM.
        # :reek:NilCheck -- nil sentinels: no CERTIFICATE block / bad base64 / trailing DER -> undefined.
        # :reek:TooManyStatements -- the PEM-blocks vs single-DER branch reads clearest inline.
        def self.keypair_certs(string)
          blocks = pem_blocks(string)
          return pem_chain_certs(blocks) unless blocks.empty?

          der = std_base64_decode(string)
          der && single_der_cert(der)
        rescue OpenSSL::OpenSSLError
          nil
        end
        private_class_method :keypair_certs

        # The CERTIFICATE blocks of a PEM input as parsed certs, ignoring any non-CERTIFICATE block, or
        # nil when none is present (Go's tls.X509KeyPair requires at least one certificate).
        def self.pem_chain_certs(blocks)
          certs = blocks.filter_map { |type, der| OpenSSL::X509::Certificate.new(der) if type == "CERTIFICATE" }
          certs.empty? ? nil : certs
        end
        private_class_method :pem_chain_certs

        # A single DER certificate as a one-element chain, rejecting trailing bytes: Go's
        # x509.ParseCertificate errors on them, but OpenSSL::X509::Certificate.new silently keeps only the
        # leading element, so the encoded length is compared against the buffer explicitly.
        # :reek:NilCheck -- nil means a truncated or trailing-padded DER (-> OPA undefined).
        def self.single_der_cert(der)
          total = leading_element_length(der)
          return nil if total.nil? || total != der.bytesize

          [OpenSSL::X509::Certificate.new(der)]
        end
        private_class_method :single_der_cert

        # The private key for this leaf, or nil unless it parses and its public half matches the leaf's
        # public key (Go's tls.X509KeyPair validates the key against the FIRST certificate).
        # :reek:NilCheck -- nil flows from keypair_key as the parse-or-mismatch sentinel.
        def self.matching_key(leaf, string)
          key = keypair_key(string)
          key if key && key_matches_leaf?(leaf, key)
        end
        private_class_method :matching_key

        # The single private key Go's tls.X509KeyPair would use, or nil when it is missing, malformed,
        # encrypted, public-only, or of a type Go's x509 does not support (all -> OPA undefined). Bounded
        # by MAX_KEY_DER_BYTES so OpenSSL::PKey.read never trial-parses an unbounded buffer.
        # :reek:NilCheck -- nil is the parse-failure sentinel.
        # :reek:TooManyStatements -- the bound + read + type-gate sequence reads clearest inline.
        def self.keypair_key(string)
          der = key_der(string)
          return nil if der.nil? || der.bytesize > MAX_KEY_DER_BYTES

          key = OpenSSL::PKey.read(der, "")
          return nil unless private_material?(key) && go_supported?(key)

          key
        rescue OpenSSL::OpenSSLError, ::ArgumentError
          nil
        end
        private_class_method :keypair_key

        # The DER of the key block Go's tls.X509KeyPair selects: the FIRST PEM block whose type is
        # "PRIVATE KEY" or "<algo> PRIVATE KEY". Go parses ONLY that block and errors if it fails — it
        # never falls through to a later block — so a malformed or wrong-typed first key block must map to
        # undefined even when a valid key follows (OpenSSL::PKey.read on the whole input would instead
        # skip to the parseable one). A non-PEM input is the raw base64-DER key.
        # :reek:NilCheck -- nil means no private-key block / bad base64 (-> OPA undefined).
        def self.key_der(string)
          blocks = pem_blocks(string)
          return std_base64_decode(string) if blocks.empty?

          _, der = blocks.find { |type, _| private_key_block?(type) }
          der
        end
        private_class_method :key_der

        # Go's tls.X509KeyPair private-key block predicate: an exact "PRIVATE KEY" or an "<algo> PRIVATE
        # KEY" (RSA / EC / …) type.
        def self.private_key_block?(type)
          type == "PRIVATE KEY" || type.end_with?(" PRIVATE KEY")
        end
        private_class_method :private_key_block?

        # Whether the private key's SubjectPublicKeyInfo matches the leaf certificate's. A public-only key
        # arg is already dropped by keypair_key.
        def self.key_matches_leaf?(leaf, key)
          leaf.public_key.public_to_der == key.public_to_der
        rescue OpenSSL::OpenSSLError
          false
        end
        private_class_method :key_matches_leaf?

        # Build the tls.Certificate struct hash. A builder failure maps to undefined rather than aborting
        # the evaluation (totality) — the structural exceptions are fully qualified because
        # Ruby::Rego::TypeError shadows ::TypeError in this module's scope.
        # :reek:NilCheck -- n/a; rescue maps OpenSSL/ASN.1 builder failures to OPA's undefined.
        # rubocop:disable Metrics/MethodLength
        def self.build_keypair_struct(certs, key)
          leaf = CertificateStruct.build(certs.first)
          leaf.delete("URIStrings") # tls.Certificate.Leaf is Go's raw x509.Certificate (no OPA injection)
          Value.from_ruby(
            "Certificate" => certs.map { |cert| Base64.strict_encode64(cert.to_der) },
            "Leaf" => leaf,
            "OCSPStaple" => nil,
            "PrivateKey" => go_struct_for(key),
            "SignedCertificateTimestamps" => nil,
            "SupportedSignatureAlgorithms" => nil
          )
        rescue OpenSSL::OpenSSLError, MalformedCertificate, SystemStackError,
               ::NoMethodError, ::TypeError, ::IndexError, ::ArgumentError, ::RangeError
          UndefinedValue.new
        end
        private_class_method :build_keypair_struct
        # rubocop:enable Metrics/MethodLength
      end
    end
  end
end

Ruby::Rego::Builtins::Crypto.register_keypairs!
