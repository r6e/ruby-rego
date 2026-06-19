# frozen_string_literal: true

require_relative "../uri/parser"

module Ruby
  module Rego
    module Builtins
      module Crypto
        # URI-SAN fields of the certificate struct (see certificate_struct.rb for the module role).
        module CertificateStruct
          # Builds the URIs / URIStrings fields from the URI SANs. crypto/x509 runs each through
          # net/url.Parse (a reject -> the whole certificate fails to parse -> OPA undefined); URIs
          # is json.Marshal of each *url.URL, URIStrings the injected url.String() of each.
          # @param uri_texts [Array[String]]
          # @return [Hash[String, untyped]]
          def self.uri_fields(uri_texts)
            parsed = parsed_uris(uri_texts)
            { "URIs" => parsed.map { |components| url_struct(components) },
              "URIStrings" => parsed.map { |components| Uri::Parser.string(components) } }
          end

          # Parse each URI SAN text into url.URL Components, raising (-> undefined) on any net/url.Parse
          # rejection, exactly as crypto/x509 does. Shared by the certificate URIs+URIStrings builder
          # and the CSR URIs builder (the CSR has no injected URIStrings field).
          # :reek:NilCheck -- nil is Parser.parse's reject sentinel (Go's url.Parse failure).
          def self.parsed_uris(uri_texts)
            uri_texts.map { |text| Uri::Parser.parse(text) || raise(MalformedCertificate, "invalid URI SAN") }
          end
          private_class_method :parsed_uris

          # json.Marshal of Go's url.URL: every exported field, with User marshaling as {} when
          # userinfo is present (its fields are unexported) and null otherwise.
          # rubocop:disable Metrics/AbcSize
          def self.url_struct(components)
            user = components.user ? {} : nil # : Hash[String, untyped]?
            {
              "Scheme" => components.scheme.to_s, "Opaque" => components.opaque.to_s,
              "User" => user,
              "Host" => components.host.to_s, "Path" => components.path.to_s,
              "RawPath" => components.raw_path.to_s, "OmitHost" => components.omit_host || false,
              "ForceQuery" => components.force_query || false, "RawQuery" => components.raw_query.to_s,
              "Fragment" => components.fragment.to_s, "RawFragment" => components.raw_fragment.to_s
            }
          end
          private_class_method :url_struct
          # rubocop:enable Metrics/AbcSize
        end
      end
    end
  end
end
