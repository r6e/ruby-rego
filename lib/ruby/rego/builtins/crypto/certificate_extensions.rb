# frozen_string_literal: true

require "openssl"

module Ruby
  module Rego
    module Builtins
      module Crypto
        # Fills the parsed-extension fields of the certificate struct by decoding each known extension's
        # DER the way crypto/x509's parseCertificate does. Each handler mutates `fields` in place.
        # rubocop:disable Metrics/ModuleLength
        module CertificateStruct
          # Go x509.ExtKeyUsage enum, keyed by the EKU purpose OID.
          EXT_KEY_USAGES = {
            "2.5.29.37.0" => 0, "1.3.6.1.5.5.7.3.1" => 1, "1.3.6.1.5.5.7.3.2" => 2,
            "1.3.6.1.5.5.7.3.3" => 3, "1.3.6.1.5.5.7.3.4" => 4, "1.3.6.1.5.5.7.3.5" => 5,
            "1.3.6.1.5.5.7.3.6" => 6, "1.3.6.1.5.5.7.3.7" => 7, "1.3.6.1.5.5.7.3.8" => 8,
            "1.3.6.1.5.5.7.3.9" => 9, "1.3.6.1.4.1.311.10.3.3" => 10, "2.16.840.1.113730.4.1" => 11,
            "1.3.6.1.4.1.311.2.1.22" => 12, "1.3.6.1.4.1.311.61.1.1" => 13
          }.freeze

          # GeneralName context tag -> [permitted field, excluded field] for nameConstraints subtrees.
          NAME_CONSTRAINT_FIELDS = {
            2 => %w[PermittedDNSDomains ExcludedDNSDomains],
            1 => %w[PermittedEmailAddresses ExcludedEmailAddresses],
            6 => %w[PermittedURIDomains ExcludedURIDomains],
            7 => %w[PermittedIPRanges ExcludedIPRanges]
          }.freeze

          # AccessDescription method OID -> the field its URI accessLocation populates.
          ACCESS_METHODS = {
            "1.3.6.1.5.5.7.48.1" => "OCSPServer",
            "1.3.6.1.5.5.7.48.2" => "IssuingCertificateURL"
          }.freeze

          # @param fields [Hash[String, untyped]]
          # @param cert [OpenSSL::X509::Certificate]
          # @return [Hash[String, untyped]]
          def self.apply_extensions(fields, cert)
            certificate_extensions(cert).each { |oid, critical, der| dispatch_extension(fields, oid, critical, der) }
            fields
          end

          # [oid, critical?, inner_der] for each extension, from an ASN.1 walk of the certificate.
          # rubocop:disable Metrics/AbcSize
          def self.certificate_extensions(cert)
            tbs = OpenSSL::ASN1.decode(cert.to_der).value[0]
            wrapper = tbs.value.find { |element| element.respond_to?(:tag) && element.tag == 3 }
            return [] unless wrapper

            wrapper.value[0].value.map do |ext|
              parts = ext.value
              critical = parts.size == 3 && parts[1].value == true
              [parts[0].oid, critical, parts.last.value]
            end
          end
          private_class_method :certificate_extensions
          # rubocop:enable Metrics/AbcSize

          # :reek:TooManyStatements -- a flat dispatch over the extension OIDs crypto/x509 parses.
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
          def self.dispatch_extension(fields, oid, critical, der)
            case oid
            when "2.5.29.14" then fields["SubjectKeyId"] = subject_key_id(der)
            when "2.5.29.35" then fields["AuthorityKeyId"] = authority_key_id(der)
            when "2.5.29.15" then fields["KeyUsage"] = key_usage(der)
            when "2.5.29.37" then ext_key_usage(fields, der)
            when "2.5.29.19" then basic_constraints(fields, der)
            when "2.5.29.17" then subject_alt_name(fields, der)
            when "2.5.29.31" then fields["CRLDistributionPoints"] = collect_uris(OpenSSL::ASN1.decode(der))
            when "1.3.6.1.5.5.7.1.1" then authority_info_access(fields, der)
            when "2.5.29.30" then name_constraints(fields, der, critical)
            when "2.5.29.32" then certificate_policies(fields, der)
            end
          end
          private_class_method :dispatch_extension
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength

          # SubjectKeyId (2.5.29.14): the keyIdentifier OCTET STRING content, base64.
          def self.subject_key_id(der)
            b64(OpenSSL::ASN1.decode(der).value)
          end
          private_class_method :subject_key_id

          # AuthorityKeyId (2.5.29.35): the [0] keyIdentifier from the AuthorityKeyIdentifier SEQUENCE.
          # :reek:NilCheck -- a SEQUENCE without the optional [0] keyIdentifier leaves AuthorityKeyId nil.
          def self.authority_key_id(der)
            key_id = OpenSSL::ASN1.decode(der).value.find { |element| context_tag?(element, 0) }
            key_id && b64(key_id.value)
          end
          private_class_method :authority_key_id

          # KeyUsage (2.5.29.15): the BIT STRING bits, MSB-first, OR-ed into Go's KeyUsage bitmask
          # (bit i -> 1 << i: DigitalSignature=1 … DecipherOnly=256).
          def self.key_usage(der)
            bytes = OpenSSL::ASN1.decode(der).value.bytes
            usage = 0
            bytes.each_with_index do |byte, byte_index|
              (0..7).each { |bit| usage |= (1 << ((byte_index * 8) + bit)) if byte.anybits?(0x80 >> bit) }
            end
            usage
          end
          private_class_method :key_usage

          # ExtKeyUsage (2.5.29.37): SEQUENCE OF purpose OID -> the Go enum ints (known) and
          # UnknownExtKeyUsage (OID int arrays) for the rest.
          def self.ext_key_usage(fields, der)
            known = [] # : Array[Integer]
            unknown = [] # : Array[untyped]
            OpenSSL::ASN1.decode(der).value.each do |purpose|
              oid = purpose.oid
              enum = EXT_KEY_USAGES[oid]
              enum ? known << enum : unknown << oid_ints(oid)
            end
            fields["ExtKeyUsage"] = known unless known.empty?
            fields["UnknownExtKeyUsage"] = unknown unless unknown.empty?
          end
          private_class_method :ext_key_usage

          # BasicConstraints (2.5.29.19): SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL }.
          # :reek:TooManyStatements -- a faithful port of parseBasicConstraintsExtension.
          # rubocop:disable Metrics/AbcSize
          def self.basic_constraints(fields, der)
            fields["BasicConstraintsValid"] = true
            elements = OpenSSL::ASN1.decode(der).value
            fields["IsCA"] = elements.any? { |element| element.is_a?(OpenSSL::ASN1::Boolean) && element.value }
            path_len = elements.find { |element| element.is_a?(OpenSSL::ASN1::Integer) }
            # Go's parseBasicConstraintsExtension defaults maxPathLen to -1 when no pathLen is encoded.
            length = path_len ? path_len.value.to_i : -1
            fields["MaxPathLen"] = length
            fields["MaxPathLenZero"] = length.zero?
          end
          private_class_method :basic_constraints
          # rubocop:enable Metrics/AbcSize

          # SubjectAltName (2.5.29.17): GeneralNames -> DNSNames/EmailAddresses/IPAddresses by tag.
          # URI SANs (tag 6) are handled by the URIs/URIStrings builder, not here.
          # :reek:TooManyStatements -- one pass over the GeneralName CHOICE alternatives.
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
          def self.subject_alt_name(fields, der)
            dns = [] # : Array[String]
            email = [] # : Array[String]
            ips = [] # : Array[String]
            uris = [] # : Array[String]
            OpenSSL::ASN1.decode(der).value.each do |general_name|
              value = general_name.value
              case general_name.tag
              when 2 then dns << value
              when 1 then email << value
              when 6 then uris << value
              when 7 then ips << go_ip_string(value)
              end
            end
            fields["DNSNames"] = dns unless dns.empty?
            fields["EmailAddresses"] = email unless email.empty?
            fields["IPAddresses"] = ips unless ips.empty?
            fields.merge!(uri_fields(uris)) unless uris.empty?
          end
          private_class_method :subject_alt_name
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength

          # AuthorityInfoAccess (1.3.6.1.5.5.7.1.1): SEQUENCE OF AccessDescription { method OID,
          # location GeneralName }; OCSP/caIssuers URI locations populate OCSPServer/IssuingCertificateURL.
          def self.authority_info_access(fields, der)
            OpenSSL::ASN1.decode(der).value.each do |description|
              access = description.value
              field = ACCESS_METHODS[access[0].oid]
              location = access[1]
              next unless field && context_tag?(location, 6)

              (fields[field] ||= []) << location.value
            end
          end
          private_class_method :authority_info_access

          # NameConstraints (2.5.29.30): SEQUENCE { [0] permittedSubtrees, [1] excludedSubtrees }.
          # PermittedDNSDomainsCritical carries the extension's critical flag regardless of content.
          def self.name_constraints(fields, der, critical)
            fields["PermittedDNSDomainsCritical"] = critical
            OpenSSL::ASN1.decode(der).value.each do |subtrees|
              column = subtrees.tag # 0 = permitted, 1 = excluded
              subtrees.value.each { |subtree| add_constraint(fields, subtree.value[0], column) }
            end
          end
          private_class_method :name_constraints

          # Append one GeneralSubtree base to its permitted/excluded field (column 0 or 1).
          def self.add_constraint(fields, base, column)
            tag = base.tag
            field, = NAME_CONSTRAINT_FIELDS[tag]&.values_at(column)
            return unless field

            raw = base.value
            (fields[field] ||= []) << (tag == 7 ? ip_net(raw) : raw)
          end
          private_class_method :add_constraint

          # CertificatePolicies (2.5.29.32): PolicyIdentifiers (OID int arrays) and Policies (dotted OIDs).
          def self.certificate_policies(fields, der)
            oids = OpenSSL::ASN1.decode(der).value.map { |info| info.value[0].oid }
            fields["PolicyIdentifiers"] = oids.map { |oid| oid_ints(oid) }
            fields["Policies"] = oids
          end
          private_class_method :certificate_policies

          # Recursively collect every primitive [6] uniformResourceIdentifier under an ASN.1 node
          # (CRL DistributionPoints nest the URI fullNames a few SEQUENCEs deep).
          def self.collect_uris(node)
            value = node.value
            return [value] if context_tag?(node, 6) && value.is_a?(String)
            return nil unless value.is_a?(Array)

            uris = value.flat_map { |child| collect_uris(child) }.compact
            uris.empty? ? nil : uris
          end
          private_class_method :collect_uris

          # json.Marshal of Go's *net.IPNet for a nameConstraints IP subtree: net.IP marshals via
          # MarshalText (its string form), net.IPMask has no MarshalText so the mask stays base64.
          def self.ip_net(bytes)
            half = bytes.bytesize / 2
            { "IP" => go_ip_string(bytes.byteslice(0, half).to_s), "Mask" => b64(bytes.byteslice(half..).to_s) }
          end
          private_class_method :ip_net

          # Whether an ASN.1 node is a context-specific element with the given tag number.
          def self.context_tag?(node, tag)
            node.respond_to?(:tag) && node.tag == tag && node.respond_to?(:tag_class) &&
              node.tag_class == :CONTEXT_SPECIFIC
          end
          private_class_method :context_tag?

          # Port of Go's net.IP.String for the raw address bytes of an iPAddress SAN (4 or 16 bytes):
          # dotted-decimal for IPv4 (and v4-in-v6), else IPv6 with one "::" run-of-zeros compression.
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
          # :reek:TooManyStatements,:reek:DuplicateMethodCall -- a faithful port of net.IP.String.
          def self.go_ip_string(bytes)
            octets = bytes.bytes
            return octets.join(".") if octets.size == 4
            return "?#{bytes.unpack1("H*")}" unless octets.size == 16
            return octets[12, 4].to_a.join(".") if v4_in_v6?(octets)

            zero_start, zero_end = longest_zero_run(octets)
            render_ipv6(octets, zero_start, zero_end)
          end
          private_class_method :go_ip_string

          def self.v4_in_v6?(octets)
            octets[0, 10].to_a.all?(&:zero?) && octets[10] == 0xff && octets[11] == 0xff
          end
          private_class_method :v4_in_v6?

          # The first longest run of zero 16-bit groups (>= 2 groups), as [start, end) byte offsets,
          # or [-1, -1] when no run qualifies for "::" compression.
          # :reek:TooManyStatements -- a faithful port of net.IP.String's zero-run scan.
          def self.longest_zero_run(octets)
            best_start = -1; best_end = -1 # rubocop:disable Style/Semicolon
            index = 0
            while index < 16
              run_end = index
              run_end += 2 while run_end < 16 && octets[run_end].zero? && octets[run_end + 1].zero?
              advanced = run_end > index
              if advanced && (run_end - index) > (best_end - best_start)
                best_start = index
                best_end = run_end
              end
              index = advanced ? run_end : index + 2
            end
            (best_end - best_start) <= 2 ? [-1, -1] : [best_start, best_end]
          end
          private_class_method :longest_zero_run

          # :reek:TooManyStatements -- a faithful port of net.IP.String's group-by-group emit.
          def self.render_ipv6(octets, zero_start, zero_end)
            out = +""
            index = 0
            while index < 16
              if index == zero_start
                out << "::"
                index = zero_end
                break if index >= 16
              elsif index.positive?
                out << ":"
              end
              out << ((octets[index] << 8) | octets[index + 1]).to_s(16)
              index += 2
            end
            out
          end
          private_class_method :render_ipv6
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
        end
        # rubocop:enable Metrics/ModuleLength
      end
    end
  end
end
