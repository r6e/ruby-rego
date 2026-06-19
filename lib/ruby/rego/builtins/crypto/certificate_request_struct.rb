# frozen_string_literal: true

require "openssl"

module Ruby
  module Rego
    module Builtins
      module Crypto
        # CSR fields of the x509 struct builder (see certificate_struct.rb for the module role). A
        # CertificateRequest is a subset of a Certificate: Subject/PublicKey/Signature/Raw* and the
        # SANs derived from the requested extensions, plus the raw Attributes set. Reuses the
        # certificate atoms (Name.build, public_key, signature_algorithm, the SAN validators via
        # general_names, parsed_uris/url_struct, scrub, b64, oid_ints, context_tag?).
        module CertificateStruct
          # PKCS#9 extensionRequest attribute OID (its value carries the requested extensions).
          EXTENSION_REQUEST_OID = "1.2.840.113549.1.9.14"

          # The CertificateRequest field hash at Go's zero values; computed fields override these.
          REQUEST_ZERO_FIELDS = {
            "Raw" => nil, "RawTBSCertificateRequest" => nil, "RawSubjectPublicKeyInfo" => nil,
            "RawSubject" => nil, "Version" => 0, "Signature" => nil, "SignatureAlgorithm" => 0,
            "PublicKeyAlgorithm" => 0, "PublicKey" => nil, "Subject" => nil,
            "Attributes" => nil, "Extensions" => nil, "ExtraExtensions" => nil,
            "DNSNames" => nil, "EmailAddresses" => nil, "IPAddresses" => nil, "URIs" => nil
          }.freeze

          # @param request [OpenSSL::X509::Request]
          # @return [Hash[String, untyped]]
          # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
          def self.build_request(request)
            decoded = OpenSSL::ASN1.decode(request.to_der)
            info = decoded.value[0] # CertificationRequestInfo: [version, subject, spki, [0] attributes]
            subject = info.value[1]
            spki = info.value[2]
            attributes = info.value.find { |element| context_tag?(element, 0) }
            algorithm = PUBLIC_KEY_ALGORITHM_OIDS.fetch(spki.value[0].value[0].oid, 0)
            fields = REQUEST_ZERO_FIELDS.merge(
              "Version" => request.version.to_i,
              "Raw" => b64(request.to_der), "RawTBSCertificateRequest" => b64(info.to_der),
              "RawSubject" => b64(subject.to_der), "RawSubjectPublicKeyInfo" => b64(spki.to_der),
              "Subject" => Name.build(subject),
              "PublicKey" => algorithm.zero? ? nil : public_key(request),
              "PublicKeyAlgorithm" => algorithm,
              "SignatureAlgorithm" => signature_algorithm(request, decoded),
              "Signature" => b64(decoded.value[2].value),
              "Attributes" => request_attributes(attributes), "Extensions" => request_extensions(attributes)
            )
            request_sans(fields, attributes)
            scrub(fields)
          end
          # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

          # The requested extensions (the extensionRequest attribute's SEQUENCE OF Extension), or nil.
          # :reek:NilCheck -- nil means the CSR carries no extensionRequest attribute (Go's zero value).
          # rubocop:disable Metrics/AbcSize
          def self.request_extension_nodes(attributes)
            return nil unless attributes

            extension_request = attributes.value.find { |attr| attr.value[0].oid == EXTENSION_REQUEST_OID }
            return nil unless extension_request

            nodes = extension_request.value[1].value[0].value
            oids = nodes.map { |ext| ext.value[0].oid }
            # Go's parseCSRExtensions rejects a repeated requested-extension OID -> OPA undefined.
            raise MalformedCertificate, "duplicate requested extension" if oids.uniq.length != oids.length

            nodes
          end
          private_class_method :request_extension_nodes
          # rubocop:enable Metrics/AbcSize

          # Extensions[] from the requested extensions (same shape as a certificate's), or nil.
          def self.request_extensions(attributes)
            request_extension_nodes(attributes)&.map { |ext| extension_entry(ext) }
          end
          private_class_method :request_extensions

          # The DNSNames/EmailAddresses/IPAddresses/URIs requested via the SAN extension. Unlike a
          # certificate, a CSR has no injected URIStrings field.
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
          def self.request_sans(fields, attributes)
            nodes = request_extension_nodes(attributes)
            san = nodes&.find { |ext| ext.value[0].oid == "2.5.29.17" }
            return unless san

            dns, email, ips, uris = general_names(san.value.last.value)
            fields["DNSNames"] = dns unless dns.empty?
            fields["EmailAddresses"] = email unless email.empty?
            fields["IPAddresses"] = ips unless ips.empty?
            fields["URIs"] = parsed_uris(uris).map { |components| url_struct(components) } unless uris.empty?
          end
          private_class_method :request_sans
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

          # The raw Attributes (pkix.AttributeTypeAndValueSET[]), mirroring Go's parseRawAttributes:
          # each attribute is interpreted as {Type, Value: SET OF SEQUENCE OF {Type, Value}}, and an
          # attribute whose value does not fit that shape (e.g. challengePassword, a plain string) is
          # silently dropped. nil when none survive.
          def self.request_attributes(attributes)
            return nil unless attributes

            sets = attributes.value.filter_map { |attr| attribute_set(attr) }
            sets.empty? ? nil : sets
          end
          private_class_method :request_attributes

          # One AttributeTypeAndValueSET, or nil if the attribute value is not SET OF SEQUENCE OF
          # AttributeTypeAndValue (Go's asn1.Unmarshal fails and the attribute is skipped).
          # :reek:TooManyStatements -- the rescue makes the "skip on unmarshal failure" explicit.
          def self.attribute_set(attr)
            groups = attr.value[1].value.map { |group| attribute_group(group) }
            { "Type" => oid_ints(attr.value[0].oid), "Value" => groups }
          rescue ::NoMethodError, ::TypeError, ::IndexError, ::ArgumentError
            nil
          end
          private_class_method :attribute_set

          # A SEQUENCE OF AttributeTypeAndValue -> [{Type, Value}]. Go reads each member as a struct
          # { type OID, value ANY } — exactly the first two elements; any trailing element (e.g. a
          # critical extension's OCTET STRING after its BOOLEAN) is ignored, not an error.
          def self.attribute_group(group)
            group.value.map do |atv|
              pair = atv.value
              { "Type" => oid_ints(pair[0].oid), "Value" => attribute_value(pair[1]) }
            end
          end
          private_class_method :attribute_group

          # json.Marshal of Go's asn1-into-`any` for the ATV value: a BOOLEAN marshals as true/false, an
          # OCTET STRING (a non-critical extension's extnValue) as base64 of its content.
          def self.attribute_value(node)
            case node
            when OpenSSL::ASN1::Boolean then node.value
            else b64(node.value)
            end
          end
          private_class_method :attribute_value
        end
      end
    end
  end
end
