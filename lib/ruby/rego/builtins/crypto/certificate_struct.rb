# frozen_string_literal: true

require "base64"
require "openssl"

module Ruby
  module Rego
    module Builtins
      module Crypto
        # Builds the JSON hash OPA emits for one certificate: json.Marshal of Go's x509.Certificate
        # plus URIStrings. Every field name and shape mirrors the Go struct exactly. Fields default to
        # Go's zero value (nil for slices/pointers, 0 for ints, false for bools) and are overridden as
        # each is derived; the parsed-extension fields are filled in by certificate_extensions.rb.
        module CertificateStruct
          # Go x509.SignatureAlgorithm enum, keyed by OpenSSL's signature-algorithm name.
          SIGNATURE_ALGORITHMS = {
            "md2WithRSAEncryption" => 1, "md5WithRSAEncryption" => 2, "sha1WithRSAEncryption" => 3,
            "sha256WithRSAEncryption" => 4, "sha384WithRSAEncryption" => 5, "sha512WithRSAEncryption" => 6,
            "dsaWithSHA1" => 7, "dsa_with_SHA256" => 8, "ecdsa-with-SHA1" => 9, "ecdsa-with-SHA256" => 10,
            "ecdsa-with-SHA384" => 11, "ecdsa-with-SHA512" => 12, "ED25519" => 16
          }.freeze

          # Go x509.PublicKeyAlgorithm enum, keyed by the key's OpenSSL oid.
          PUBLIC_KEY_ALGORITHMS = { "rsaEncryption" => 1, "id-ecPublicKey" => 3, "ED25519" => 4 }.freeze

          # The certificate field hash at Go's zero values; computed fields override these.
          ZERO_FIELDS = {
            "Raw" => nil, "RawTBSCertificate" => nil, "RawSubjectPublicKeyInfo" => nil,
            "RawSubject" => nil, "RawIssuer" => nil,
            "Signature" => nil, "SignatureAlgorithm" => 0,
            "PublicKeyAlgorithm" => 0, "PublicKey" => nil,
            "Version" => 0, "SerialNumber" => 0, "Issuer" => nil, "Subject" => nil,
            "NotBefore" => nil, "NotAfter" => nil, "KeyUsage" => 0,
            "Extensions" => nil, "ExtraExtensions" => nil, "UnhandledCriticalExtensions" => nil,
            "ExtKeyUsage" => nil, "UnknownExtKeyUsage" => nil,
            "BasicConstraintsValid" => false, "IsCA" => false,
            "MaxPathLen" => 0, "MaxPathLenZero" => false,
            "SubjectKeyId" => nil, "AuthorityKeyId" => nil,
            "OCSPServer" => nil, "IssuingCertificateURL" => nil,
            "DNSNames" => nil, "EmailAddresses" => nil, "IPAddresses" => nil,
            "URIs" => nil, "URIStrings" => nil,
            "PermittedDNSDomainsCritical" => false,
            "PermittedDNSDomains" => nil, "ExcludedDNSDomains" => nil,
            "PermittedIPRanges" => nil, "ExcludedIPRanges" => nil,
            "PermittedEmailAddresses" => nil, "ExcludedEmailAddresses" => nil,
            "PermittedURIDomains" => nil, "ExcludedURIDomains" => nil,
            "CRLDistributionPoints" => nil,
            "PolicyIdentifiers" => nil, "Policies" => nil, "PolicyMappings" => nil,
            "InhibitAnyPolicy" => 0, "InhibitAnyPolicyZero" => false,
            "InhibitPolicyMapping" => 0, "InhibitPolicyMappingZero" => false,
            "RequireExplicitPolicy" => 0, "RequireExplicitPolicyZero" => false
          }.freeze

          # @param cert [OpenSSL::X509::Certificate]
          # @return [Hash[String, untyped]]
          # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
          def self.build(cert)
            decoded = OpenSSL::ASN1.decode(cert.to_der)
            tbs = decoded.value[0]
            elements = tbs.value
            # TBSCertificate omits the [0] EXPLICIT version field for v1 certs, shifting serialNumber
            # to index 0 (it sits at index 1 once a version is present) and every later field with it.
            serial_index = context_tag?(elements[0], 0) ? 1 : 0
            issuer = elements[serial_index + 2]
            subject = elements[serial_index + 4]
            spki = elements[serial_index + 5]
            fields = ZERO_FIELDS.merge(
              scalar_fields(cert, decoded),
              raw_fields(cert, tbs, issuer, subject, spki),
              "PublicKey" => CertificateStruct.public_key(cert),
              "PublicKeyAlgorithm" => PUBLIC_KEY_ALGORITHMS.fetch(cert.public_key.oid, 0),
              "Issuer" => Name.build(issuer),
              "Subject" => Name.build(subject),
              "Extensions" => extension_list(tbs)
            )
            apply_extensions(fields, cert)
          end
          # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

          # Scalars available directly from the certificate accessors. `decoded` is the certificate's
          # decoded ASN.1 (SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }).
          def self.scalar_fields(cert, decoded)
            {
              "Version" => cert.version + 1,
              "SerialNumber" => cert.serial.to_i,
              "NotBefore" => rfc3339(cert.not_before),
              "NotAfter" => rfc3339(cert.not_after),
              "SignatureAlgorithm" => SIGNATURE_ALGORITHMS.fetch(cert.signature_algorithm, 0),
              "Signature" => b64(decoded.value[2].value)
            }
          end
          private_class_method :scalar_fields

          # The Raw* sub-DER slices, lifted from the certificate's ASN.1 tree (Go keeps these as the
          # exact encoded bytes). issuer/subject/spki are the already-located TBSCertificate elements
          # (their indices depend on whether the optional version field is present).
          def self.raw_fields(cert, tbs, issuer, subject, spki)
            {
              "Raw" => b64(cert.to_der),
              "RawTBSCertificate" => b64(tbs.to_der),
              "RawIssuer" => b64(issuer.to_der),
              "RawSubject" => b64(subject.to_der),
              "RawSubjectPublicKeyInfo" => b64(spki.to_der)
            }
          end
          private_class_method :raw_fields

          # The Extensions[] array: {Critical, Id (OID as integer array), Value (base64 of the raw DER
          # octet content)} in certificate order.
          # rubocop:disable Metrics/AbcSize
          def self.extension_list(tbs)
            wrapper = tbs.value.find { |element| element.respond_to?(:tag) && element.tag == 3 }
            return nil unless wrapper

            wrapper.value[0].value.map do |ext|
              parts = ext.value
              critical = parts.size == 3 && parts[1].value
              { "Critical" => critical == true, "Id" => oid_ints(parts[0].oid), "Value" => b64(parts.last.value) }
            end
          end
          private_class_method :extension_list
          # rubocop:enable Metrics/AbcSize

          # OID dotted string -> array of integer arcs (Go marshals asn1.ObjectIdentifier as []int).
          def self.oid_ints(oid)
            oid.split(".").map { |arc| Integer(arc) }
          end

          def self.rfc3339(time)
            time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
          end
          private_class_method :rfc3339

          def self.b64(bytes)
            Base64.strict_encode64(bytes)
          end
        end
      end
    end
  end
end

require_relative "certificate_name"
require_relative "certificate_public_key"
require_relative "certificate_extensions"
require_relative "certificate_uri"
