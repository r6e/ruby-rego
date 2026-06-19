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
      # rubocop:disable Metrics/ModuleLength
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
        # :reek:NilCheck -- nil is the parse-failure sentinel from keypair_cert_ders / matching_key.
        # :reek:TooManyStatements -- a faithful port of OPA's keypair parse + validation flow.
        # rubocop:disable Metrics/AbcSize
        def self.parse_keypair(cert_value, key_value)
          cert_string = string_value(cert_value, "crypto.x509.parse_keypair")
          key_string = string_value(key_value, "crypto.x509.parse_keypair")
          return UndefinedValue.new unless scannable?(cert_string) && scannable?(key_string)

          cert_ders = keypair_cert_ders(cert_string)
          return UndefinedValue.new if cert_ders.nil?

          leaf = leaf_certificate(cert_ders.first)
          return UndefinedValue.new if leaf.nil?

          key = matching_key(leaf, key_string)
          return UndefinedValue.new if key.nil?

          build_keypair_struct(cert_ders, leaf, key)
        end
        # rubocop:enable Metrics/AbcSize

        # The RAW DER of each certificate, the way Go's tls.X509KeyPair collects them: it stores the
        # certificate bytes verbatim and parses ONLY the leaf (certs[0]), so an unparseable INTERMEDIATE
        # is kept as-is. A PEM input contributes every CERTIFICATE block's bytes and ignores other blocks
        # (a key block, comments); a non-PEM input is ONE base64-DER certificate (Go's x509.ParseCertificate
        # rejects trailing bytes, so the length is checked; OpenSSL tolerates them); base64-of-PEM is
        # decoded by pem_blocks then scanned as PEM. At least one CERTIFICATE block is required.
        # :reek:NilCheck -- nil sentinels: no CERTIFICATE block / bad base64 / trailing DER -> undefined.
        # :reek:TooManyStatements -- the PEM-blocks vs single-DER branch reads clearest inline.
        def self.keypair_cert_ders(string)
          blocks = pem_blocks(string)
          unless blocks.empty?
            ders = blocks.filter_map { |type, der| der if type == "CERTIFICATE" }
            return ders.empty? ? nil : ders
          end

          single_der(std_base64_decode(string))
        end
        private_class_method :keypair_cert_ders

        # A lone base64-DER certificate as a one-element list, or nil if it is truncated or carries
        # trailing bytes: Go's x509.ParseCertificate errors on trailing data, but OpenSSL keeps only the
        # leading element, so the encoded length is compared against the buffer explicitly.
        # :reek:NilCheck -- nil means bad base64 / a trailing-padded or truncated DER (-> OPA undefined).
        def self.single_der(der)
          return nil if der.nil?

          total = leading_element_length(der)
          total == der.bytesize ? [der] : nil
        end
        private_class_method :single_der

        # The parsed leaf certificate (certs[0]), or nil if it does not parse — Go's tls.X509KeyPair
        # parses the leaf for the Leaf field and the key match and errors if it fails (intermediates are
        # not parsed).
        # :reek:NilCheck -- nil is the leaf-parse-failure sentinel.
        def self.leaf_certificate(der)
          der && OpenSSL::X509::Certificate.new(der)
        rescue OpenSSL::OpenSSLError
          nil
        end
        private_class_method :leaf_certificate

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
          return raw_base64_key(std_base64_decode(string)) if blocks.empty?

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

        # A raw base64-DER key, or nil to drop trailing bytes the way Go's parsePrivateKey does: a bare
        # PKCS#1 RSAPrivateKey rejects trailing bytes (ParsePKCS1 checks the asn1 rest), while PKCS#8 and
        # SEC1 tolerate them. OpenSSL::PKey.read tolerates all three, so a trailing-padded PKCS#1 key —
        # which OPA returns undefined for — is dropped here; a PEM block never has trailing bytes.
        # :reek:NilCheck -- nil means bad base64 / over the size bound (-> OPA undefined).
        # :reek:TooManyStatements -- the bound + trailing check + PKCS#1 branch reads clearest inline.
        def self.raw_base64_key(der)
          return nil if der.nil?

          size = der.bytesize
          return nil if size > MAX_KEY_DER_BYTES # bound before pkcs1_rsa?'s PKey.read

          total = leading_element_length(der)
          return der if total.nil? || total == size # no trailing; PKey.read handles every form

          pkcs1_rsa?(der.byteslice(0, total).to_s) ? nil : der
        end
        private_class_method :raw_base64_key

        # True when der is a bare PKCS#1 RSAPrivateKey — the one private-key form Go's parsePrivateKey
        # rejects trailing bytes for (PKCS#8 and SEC1 tolerate them). OpenSSL re-encodes an RSA key as
        # PKCS#1, so a PKCS#1 input round-trips to itself while a PKCS#8 RSA input does not; PKey.read is
        # d2i (depth-capped), and der is the already length-checked leading element.
        # :reek:NilCheck -- n/a; the rescue maps a non-key DER to false.
        def self.pkcs1_rsa?(der)
          key = OpenSSL::PKey.read(der, "") # "" passphrase: fail cleanly on an encrypted key, never prompt
          key.is_a?(OpenSSL::PKey::RSA) && key.to_der == der
        rescue OpenSSL::OpenSSLError, ::ArgumentError
          false
        end
        private_class_method :pkcs1_rsa?

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
        def self.build_keypair_struct(cert_ders, leaf, key)
          leaf_struct = CertificateStruct.build(leaf)
          leaf_struct.delete("URIStrings") # tls.Certificate.Leaf is Go's raw x509.Certificate (no injection)
          Value.from_ruby(
            "Certificate" => cert_ders.map { |der| Base64.strict_encode64(der) },
            "Leaf" => leaf_struct,
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
      # rubocop:enable Metrics/ModuleLength
    end
  end
end

Ruby::Rego::Builtins::Crypto.register_keypairs!
