# frozen_string_literal: true

require "base64"
require "openssl"

module Ruby
  module Rego
    module Builtins
      # crypto.x509.parse_certificate_request — parse one PEM / base64-DER PKCS#10 certificate request
      # into the JSON shape OPA emits: json.Marshal of Go's x509.CertificateRequest (a single object,
      # not an array). Reuses the certificate machinery's atoms (Name, public key, signature algorithm,
      # the ASN.1 depth/type guards, the SAN validators, scrub) since a CSR is a strict subset of a
      # certificate's fields — no validity, issuer, or the dozen parsed extensions a certificate carries.
      module Crypto
        REQUEST_FUNCTIONS = {
          "crypto.x509.parse_certificate_request" => { arity: 1, handler: :parse_certificate_request }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register_requests!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, REQUEST_FUNCTIONS)
          registry
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        # :reek:NilCheck -- nil is request_from's parse-failure sentinel (-> OPA undefined).
        def self.parse_certificate_request(value)
          string = string_value(value, "crypto.x509.parse_certificate_request")
          return UndefinedValue.new unless scannable?(string)

          request = request_from(string)
          return UndefinedValue.new if request.nil?

          build_request_struct(request)
        end

        # OPA's getX509CertificateRequest: a single request, PEM ("CERTIFICATE REQUEST" block) or
        # base64-DER. Anything else (a certificate, garbage, empty) is undefined.
        # :reek:NilCheck -- nil is the parse-failure sentinel mapped to OPA's undefined.
        def self.request_from(string)
          der = string.start_with?("-----BEGIN") ? pem_request_der(string) : std_base64_decode(string)
          return nil unless der

          OpenSSL::X509::Request.new(der)
        rescue OpenSSL::OpenSSLError
          nil
        end
        private_class_method :request_from

        # The DER of the single "CERTIFICATE REQUEST" PEM block, or nil if the input is not exactly that.
        # :reek:NilCheck -- nil flows from pem_blocks as the failure sentinel.
        def self.pem_request_der(string)
          blocks = pem_blocks(string)
          type, der = blocks[0]
          der if blocks.length == 1 && type == "CERTIFICATE REQUEST"
        end
        private_class_method :pem_request_der

        # Build the struct, mapping a structural failure (a malformed known field) to OPA's undefined
        # rather than aborting the evaluation. The structural exceptions are fully qualified —
        # Ruby::Rego::TypeError shadows ::TypeError in this module's scope.
        # :reek:NilCheck -- n/a; rescue maps OpenSSL/ASN.1 builder failures to OPA's undefined.
        def self.build_request_struct(request)
          Value.from_ruby(CertificateStruct.build_request(request))
        rescue OpenSSL::OpenSSLError, MalformedCertificate, SystemStackError,
               ::NoMethodError, ::TypeError, ::IndexError, ::ArgumentError, ::RangeError
          UndefinedValue.new
        end
        private_class_method :build_request_struct
      end
    end
  end
end

require_relative "certificate_request_struct"

Ruby::Rego::Builtins::Crypto.register_requests!
