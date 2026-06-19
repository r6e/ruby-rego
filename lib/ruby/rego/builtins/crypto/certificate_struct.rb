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

          # Go x509.PublicKeyAlgorithm enum, keyed by the SubjectPublicKeyInfo algorithm OID. Keying on
          # the DER OID (not OpenSSL's key object) lets an unsupported algorithm (e.g. X25519/Ed448,
          # whose key OpenSSL cannot expose) map to UnknownPublicKeyAlgorithm(0) without raising.
          PUBLIC_KEY_ALGORITHM_OIDS = {
            "1.2.840.113549.1.1.1" => 1, "1.2.840.10040.4.1" => 2,
            "1.2.840.10045.2.1" => 3, "1.3.101.112" => 4
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
            # A 0 (unknown) algorithm has PublicKey null and never calls cert.public_key (it raises for
            # key types OpenSSL cannot represent), matching Go's UnknownPublicKeyAlgorithm handling.
            algorithm = PUBLIC_KEY_ALGORITHM_OIDS.fetch(spki.value[0].value[0].oid, 0)
            fields = ZERO_FIELDS.merge(
              scalar_fields(cert, decoded),
              raw_fields(cert, tbs, issuer, subject, spki),
              "PublicKey" => algorithm.zero? ? nil : CertificateStruct.public_key(cert),
              "PublicKeyAlgorithm" => algorithm,
              "Issuer" => Name.build(issuer),
              "Subject" => Name.build(subject),
              "Extensions" => extension_list(tbs)
            )
            scrub(apply_extensions(fields, tbs))
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
              "SerialNumber" => serial_number(cert),
              "NotBefore" => rfc3339(cert.not_before),
              "NotAfter" => rfc3339(cert.not_after),
              "SignatureAlgorithm" => signature_algorithm(cert, decoded),
              "Signature" => b64(decoded.value[2].value)
            }
          end
          private_class_method :scalar_fields

          # Go's ParseCertificate rejects a negative serial number (RFC 5280 forbids it) -> OPA undefined.
          def self.serial_number(cert)
            value = cert.serial.to_i
            raise MalformedCertificate, "negative serial number" if value.negative?

            value
          end
          private_class_method :serial_number

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

          # The raw Extension nodes (the [3] EXPLICIT wrapper's SEQUENCE OF Extension), or nil when the
          # certificate carries no extensions. Shared by extension_list and the extension parsers.
          def self.extension_nodes(tbs)
            wrapper = tbs.value.find { |element| context_tag?(element, 3) }
            return nil unless wrapper

            wrapper.value[0].value
          end

          # The Extensions[] array: {Critical, Id (OID as integer array), Value (base64 of the raw DER
          # octet content)} in certificate order; nil when there are no extensions.
          # :reek:NilCheck -- a certificate without extensions has Extensions = nil (Go's zero value).
          def self.extension_list(tbs)
            nodes = extension_nodes(tbs)
            nodes&.map { |ext| extension_entry(ext) }
          end
          private_class_method :extension_list

          # One Extensions[] entry from an Extension SEQUENCE node. Go decodes pkix.Extension
          # { Id OID, Critical BOOLEAN OPTIONAL, Value OCTET STRING } positionally and ignores any
          # trailing element: the OID, then an optional BOOLEAN critical, then the OCTET STRING value.
          # A certificate's extensions are pre-validated by OpenSSL; a CSR's requested extensions are
          # parsed raw, so an ill-formed one (no OID / no OCTET STRING value) maps to OPA's undefined.
          # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
          def self.extension_entry(ext)
            parts = ext.value
            raise MalformedCertificate, "malformed extension" unless parts[0].is_a?(OpenSSL::ASN1::ObjectId)

            index = 1
            critical = false
            if parts[index].is_a?(OpenSSL::ASN1::Boolean)
              critical = parts[index].value
              index += 1
            end
            value = parts[index]
            raise MalformedCertificate, "malformed extension" unless value.is_a?(OpenSSL::ASN1::OctetString)

            { "Critical" => critical, "Id" => oid_ints(parts[0].oid), "Value" => b64(value.value) }
          end
          private_class_method :extension_entry
          # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

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
          private_class_method :b64

          # Transcode raw bytes from an ASN.1 string encoding to UTF-8, replacing invalid bytes with
          # U+FFFD as Go's json.Marshal does. Shared by the pkix.Name builder and the CSR attribute
          # value marshaler (both reproduce Go's asn1 string decoding). Called cross-module, so public.
          # :reek:UtilityFunction -- a pure byte-encoding transform.
          def self.transcode(bytes, encoding)
            bytes.dup.force_encoding(encoding).encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
          end

          # Whether an ASN.1 node is a context-specific element with the given tag number. Shared by the
          # struct builder and the extension parsers (both reopen this module).
          def self.context_tag?(node, tag)
            node.respond_to?(:tag) && node.tag == tag && node.respond_to?(:tag_class) &&
              node.tag_class == :CONTEXT_SPECIFIC
          end
          private_class_method :context_tag?
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
