# frozen_string_literal: true

require "openssl"

module Ruby
  module Rego
    module Builtins
      module Crypto
        # Builds the Go pkix.Name JSON from a certificate's RDNSequence ASN.1, mirroring Go's
        # FillFromRDNSequence: the standard attribute OIDs populate the typed fields (Country, Org, …
        # as string arrays; CommonName / SerialNumber as strings), and every attribute also appears in
        # Names[] as {Type: OID-int-array, Value}. ExtraNames is nil for a parsed name.
        module Name
          # Attribute OID -> [pkix.Name field, multi-valued?]. Multi-valued fields are string arrays.
          ATTRIBUTE_FIELDS = {
            "2.5.4.6" => ["Country", true], "2.5.4.10" => ["Organization", true],
            "2.5.4.11" => ["OrganizationalUnit", true], "2.5.4.7" => ["Locality", true],
            "2.5.4.8" => ["Province", true], "2.5.4.9" => ["StreetAddress", true],
            "2.5.4.17" => ["PostalCode", true], "2.5.4.3" => ["CommonName", false],
            "2.5.4.5" => ["SerialNumber", false]
          }.freeze

          NAME_FIELDS = %w[Country Organization OrganizationalUnit Locality Province StreetAddress
                           PostalCode SerialNumber CommonName Names ExtraNames].freeze

          # @param rdn_sequence [OpenSSL::ASN1::Sequence] the Name's RDNSequence element
          # @return [Hash[String, untyped]]
          # :reek:TooManyStatements -- a faithful port of pkix.Name.FillFromRDNSequence's single pass.
          # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
          def self.build(rdn_sequence)
            # CommonName/SerialNumber are Go `string` fields (zero value ""); the rest are slices (nil).
            name = NAME_FIELDS.to_h { |field| [field, nil] } # : Hash[String, untyped]
            name["CommonName"] = name["SerialNumber"] = ""
            names = [] # : Array[untyped]
            rdn_sequence.value.each do |rdn|
              rdn.value.each do |attribute|
                type_and_value = attribute.value
                oid = type_and_value[0].oid
                value = type_and_value[1].value.to_s
                names << { "Type" => CertificateStruct.oid_ints(oid), "Value" => value }
                assign(name, oid, value)
              end
            end
            name["Names"] = names
            name
          end
          # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

          # Populate the typed field for a standard attribute OID (array fields accumulate; CommonName
          # and SerialNumber take the value directly, last-wins like Go).
          def self.assign(name, oid, value)
            field, multi = ATTRIBUTE_FIELDS[oid]
            return unless field

            if multi
              (name[field] ||= []) << value
            else
              name[field] = value
            end
          end
          private_class_method :assign
        end
      end
    end
  end
end
