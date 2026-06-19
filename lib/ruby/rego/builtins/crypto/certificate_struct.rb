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
        # rubocop:disable Metrics/ModuleLength
        module CertificateStruct
          # Go x509.SignatureAlgorithm enum, keyed by OpenSSL's signature-algorithm name. RSA-PSS shares
          # one OID across digests (the digest lives in the parameters), so 13/14/15 are resolved from
          # those parameters in pss_signature_algorithm, not this table.
          SIGNATURE_ALGORITHMS = {
            "md2WithRSAEncryption" => 1, "md5WithRSAEncryption" => 2, "sha1WithRSAEncryption" => 3,
            "sha256WithRSAEncryption" => 4, "sha384WithRSAEncryption" => 5, "sha512WithRSAEncryption" => 6,
            "dsaWithSHA1" => 7, "dsa_with_SHA256" => 8, "ecdsa-with-SHA1" => 9, "ecdsa-with-SHA256" => 10,
            "ecdsa-with-SHA384" => 11, "ecdsa-with-SHA512" => 12, "ED25519" => 16
          }.freeze

          # OpenSSL's name for the RSASSA-PSS signature algorithm, and the SHA-{256,384,512} digest OIDs
          # in its parameters -> Go's SHA*WithRSAPSS enum values.
          RSA_PSS_NAME = "rsassaPss"
          PSS_DIGEST_ALGORITHMS = {
            "2.16.840.1.101.3.4.2.1" => 13, "2.16.840.1.101.3.4.2.2" => 14, "2.16.840.1.101.3.4.2.3" => 15
          }.freeze

          # Go x509.PublicKeyAlgorithm enum, keyed by the key's OpenSSL oid.
          PUBLIC_KEY_ALGORITHMS = {
            "rsaEncryption" => 1, "DSA" => 2, "id-ecPublicKey" => 3, "ED25519" => 4
          }.freeze

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
            scrub(apply_extensions(fields, cert))
          end
          # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

          # Re-encode every string in the field tree to valid UTF-8, replacing invalid bytes with U+FFFD
          # exactly as Go's json.Marshal does for the raw-byte fields (URI SAN components, pkix.Name
          # attribute values). This also normalizes the ASCII-8BIT tag OpenSSL hands back so the result
          # serializes to JSON without raising. dNSName/email SANs are rejected upstream, matching Go.
          def self.scrub(value)
            case value
            when ::String then value.dup.force_encoding(Encoding::UTF_8).scrub
            when ::Array then value.map { |element| scrub(element) }
            when ::Hash then value.transform_values { |element| scrub(element) }
            else value
            end
          end
          private_class_method :scrub

          # Scalars available directly from the certificate accessors. `decoded` is the certificate's
          # decoded ASN.1 (SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }).
          def self.scalar_fields(cert, decoded)
            {
              "Version" => cert.version + 1,
              "SerialNumber" => cert.serial.to_i,
              "NotBefore" => rfc3339(cert.not_before),
              "NotAfter" => rfc3339(cert.not_after),
              "SignatureAlgorithm" => signature_algorithm(cert, decoded),
              "Signature" => b64(decoded.value[2].value)
            }
          end
          private_class_method :scalar_fields

          # Go's x509.SignatureAlgorithm enum value. RSA-PSS is read from the signatureAlgorithm
          # parameters (the [0] hashAlgorithm digest OID); everything else from the algorithm name.
          # rubocop:disable Metrics/AbcSize
          def self.signature_algorithm(cert, decoded)
            name = cert.signature_algorithm
            return SIGNATURE_ALGORITHMS.fetch(name, 0) unless name == RSA_PSS_NAME

            parameters = decoded.value[1].value[1]
            hash = parameters.value.find { |element| element.respond_to?(:tag) && element.tag.zero? }
            hash ? PSS_DIGEST_ALGORITHMS.fetch(hash.value[0].value[0].oid, 0) : 0
          end
          private_class_method :signature_algorithm
          # rubocop:enable Metrics/AbcSize

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
        # rubocop:enable Metrics/ModuleLength
      end
    end
  end
end

require_relative "certificate_name"
require_relative "certificate_public_key"
require_relative "certificate_extensions"
require_relative "certificate_uri"
