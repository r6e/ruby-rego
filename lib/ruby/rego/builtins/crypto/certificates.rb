# frozen_string_literal: true

require "base64"
require "openssl"
require_relative "../uri/parser"

module Ruby
  module Rego
    module Builtins
      # crypto.x509.parse_certificates — parse one or more X.509 certificates (PEM or base64-DER) into
      # the JSON shape OPA emits, which is byte-for-byte json.Marshal of Go's x509.Certificate struct
      # plus an injected URIStrings field (the string forms of the URI SANs). Reopens Crypto so it
      # shares string_value / std_base64_decode / the PEM scanner with the key parsers.
      #
      # Reproducing that output means re-deriving Go's parsed x509 fields from Ruby OpenSSL: the scalar
      # accessors and public key come from OpenSSL::X509::Certificate, the Raw* sub-DER slices and the
      # raw Extensions[] values from an OpenSSL::ASN1 walk of the certificate DER, and the ~15 parsed
      # extension fields (SANs, key usage, name constraints, policies, …) from parsing each extension's
      # DER the way crypto/x509 does. CertificateStruct builds the field hash.
      module Crypto
        # Raised when a known extension is structurally malformed (e.g. a URI SAN that net/url.Parse
        # rejects). Go's parseCertificate returns an error in that case, so OPA returns undefined.
        class MalformedCertificate < StandardError; end

        CERTIFICATE_FUNCTIONS = {
          "crypto.x509.parse_certificates" => { arity: 1, handler: :parse_certificates }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register_certificates!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, CERTIFICATE_FUNCTIONS)
          registry
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        # :reek:NilCheck -- nil is certificates_from's "a block failed to parse" sentinel (-> undefined).
        def self.parse_certificates(value)
          string = string_value(value, "crypto.x509.parse_certificates")
          return UndefinedValue.new unless scannable?(string)

          certs = certificates_from(string)
          return UndefinedValue.new if certs.nil?

          build_structs(certs)
        end

        # Build the struct hash for every parsed certificate. A malformed *known* extension makes Go's
        # parseCertificate return an error, so OPA returns undefined for the whole call; a decode error
        # in the field builder maps to that same undefined rather than aborting the evaluation.
        # :reek:NilCheck -- n/a; rescue maps OpenSSL/ASN.1 builder failures to OPA's undefined.
        def self.build_structs(certs)
          Value.from_ruby(certs.map { |cert| CertificateStruct.build(cert) })
        rescue OpenSSL::OpenSSLError, MalformedCertificate
          UndefinedValue.new
        end
        private_class_method :build_structs

        # OPA's getX509CertsFromString: input starting with "-----BEGIN" is parsed as PEM (every block
        # must be a CERTIFICATE, else the whole call is undefined); otherwise it is std-base64-decoded
        # and parsed as one or more concatenated DER certs (a decode failure -> undefined). Returns the
        # OpenSSL::X509::Certificate list, or nil on a parse failure.
        # :reek:NilCheck -- nil flows from std_base64_decode / der_certificates as the failure sentinel.
        def self.certificates_from(string)
          return pem_certificates(string) if string.start_with?("-----BEGIN")

          decoded = std_base64_decode(string) || (return nil)
          der_certificates(decoded)
        end
        private_class_method :certificates_from

        # Parse a buffer of one or more concatenated DER certificates (the base64 input path).
        # rubocop:disable Metrics/MethodLength
        def self.der_certificates(der)
          certs = [] # : Array[untyped]
          rest = der
          until rest.empty?
            total = leading_element_length(rest) || (return nil)
            return nil if total > rest.bytesize

            certs << OpenSSL::X509::Certificate.new(rest.byteslice(0, total).to_s)
            rest = rest.byteslice(total..).to_s
          end
          certs
        rescue OpenSSL::OpenSSLError
          nil
        end
        private_class_method :der_certificates
        # rubocop:enable Metrics/MethodLength

        # Parse the PEM blocks: OPA's getX509CertsFromPem requires every recognized block to be a
        # CERTIFICATE (a non-cert block -> undefined) and at least one block; trailing non-PEM text is
        # ignored, matching pem.Decode. Returns nil on any of those failures.
        def self.pem_certificates(string)
          blocks = pem_blocks(string)
          return nil if blocks.empty?

          blocks.map do |type, der|
            return nil unless type == "CERTIFICATE"

            OpenSSL::X509::Certificate.new(der) rescue (return nil) # rubocop:disable Style/RescueModifier
          end
        end
        private_class_method :pem_certificates
      end
    end
  end
end

require_relative "certificate_struct"

Ruby::Rego::Builtins::Crypto.register_certificates!
