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

          certs = certificates_from(cert_string)
          return UndefinedValue.new if certs.nil? || certs.empty?

          key = matching_key(certs.first, key_string)
          return UndefinedValue.new if key.nil?

          build_keypair_struct(certs, key)
        end

        # The private key for this leaf, or nil unless it parses and its public half matches the leaf's
        # public key (Go's tls.X509KeyPair validates the key against the FIRST certificate).
        # :reek:NilCheck -- nil flows from keypair_key as the parse-or-mismatch sentinel.
        def self.matching_key(leaf, string)
          key = keypair_key(string)
          key if key && key_matches_leaf?(leaf, key)
        end
        private_class_method :matching_key

        # The single private key from a PEM or base64-DER input, or nil when it is missing, encrypted,
        # public-only, or of a type Go's x509 does not support (all -> OPA undefined). Bounded by
        # MAX_KEY_DER_BYTES so OpenSSL::PKey.read never trial-parses an unbounded buffer.
        # :reek:NilCheck -- nil is the parse-failure sentinel.
        # :reek:TooManyStatements -- the bound + read + type-gate sequence reads clearest inline.
        def self.keypair_key(string)
          data = pem_or_base64(string)
          return nil if data.nil? || data.bytesize > MAX_KEY_DER_BYTES

          key = OpenSSL::PKey.read(data, "")
          return nil unless private_material?(key) && go_supported?(key)

          key
        rescue OpenSSL::OpenSSLError, ::ArgumentError
          nil
        end
        private_class_method :keypair_key

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
