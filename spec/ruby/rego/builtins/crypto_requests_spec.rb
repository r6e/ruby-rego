# frozen_string_literal: true

require "json"

# crypto.x509.parse_certificate_request — parse one PEM / base64-DER PKCS#10 CSR into the JSON shape
# OPA emits (json.Marshal of Go's x509.CertificateRequest, a single object). Every expected value is
# captured byte-for-byte from `opa eval` 1.17 (goldens.json) against committed throwaway CSRs
# spanning the key / SAN / attribute cross-product, plus the PEM/base64 dispatch and malformed edges,
# so the suite measures real OPA compatibility. Edge inputs are stored with their expected values in
# the golden file so the two can never drift apart.
# rubocop:disable Metrics/BlockLength
RSpec.describe "crypto.x509.parse_certificate_request" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  fixtures = File.expand_path("../../../fixtures/crypto_requests", __dir__)
  goldens = JSON.parse(File.read(File.join(fixtures, "goldens.json")))

  # goldens.json marks an undefined OPA result with this sentinel (JSON cannot represent "absent").
  undef_sentinel = "__undef__"

  resolve = lambda do |registry, string|
    result = registry.call("crypto.x509.parse_certificate_request", [Ruby::Rego::StringValue.new(string)])
    result.is_a?(Ruby::Rego::UndefinedValue) ? undef_sentinel : result.to_ruby
  end

  describe "CSR fixtures (every field vs OPA)" do
    goldens.fetch("requests").each do |name, expected|
      it "matches OPA on the #{name} request" do
        pem = File.read(File.join(fixtures, "#{name}.pem"))
        expect(resolve.call(registry, pem)).to eq(expected)
      end
    end
  end

  describe "input dispatch and totality edge cases" do
    goldens.fetch("edges").each do |name, expected|
      it "matches OPA on the #{name} edge input" do
        input = goldens.fetch("edge_inputs").fetch(name)
        expect(resolve.call(registry, input)).to eq(expected)
      end
    end
  end

  # Documented, accepted divergence: a deliberately-malformed PKCS#10 attribute whose value is not the
  # required `SET OF` (absent, or a non-SET type) is rejected by OpenSSL's strict Attribute-schema
  # decoder, so `OpenSSL::X509::Request.new` raises and the gem returns undefined. Go's RawValue-based
  # parser tolerates it — `opa eval` SKIPS the bad attribute and returns the parsed CSR struct
  # (Extensions null). Reachable only by hand-assembled DER (no conforming tool emits it); accepted as
  # the same structural limitation as the exotic-ATV-value case (OpenSSL as the ASN.1 layer is stricter
  # than Go). This test pins the gem's undefined result so a future change can't silently shift it.
  describe "malformed-attribute CSRs OpenSSL rejects but OPA keeps (accepted divergence)" do
    asn1 = OpenSSL::ASN1
    ext_req_oid = "1.2.840.113549.1.9.14"
    key = OpenSSL::PKey::EC.generate("prime256v1")

    build_csr = lambda do |attributes|
      subject = asn1.decode(OpenSSL::X509::Name.parse("/CN=t").to_der)
      spki = asn1.decode(key.public_to_der)
      info = asn1::Sequence.new([asn1::Integer.new(0), subject, spki,
                                 asn1::ASN1Data.new(attributes, 0, :CONTEXT_SPECIFIC)])
      signature = key.sign(OpenSSL::Digest.new("SHA256"), info.to_der)
      der = asn1::Sequence.new([info, asn1::Sequence.new([asn1::ObjectId.new("ecdsa-with-SHA256")]),
                                asn1::BitString.new(signature)]).to_der
      "-----BEGIN CERTIFICATE REQUEST-----\n#{[der].pack("m0").scan(/.{1,64}/).join("\n")}\n" \
        "-----END CERTIFICATE REQUEST-----\n"
    end

    {
      "extensionRequest with no value element" => [asn1::Sequence.new([asn1::ObjectId.new(ext_req_oid)])],
      "extensionRequest whose value is not a SET" =>
        [asn1::Sequence.new([asn1::ObjectId.new(ext_req_oid), asn1::PrintableString.new("x")])]
    }.each do |description, attributes|
      it "is undefined for a #{description} (OPA returns a struct)" do
        result = registry.call("crypto.x509.parse_certificate_request",
                               [Ruby::Rego::StringValue.new(build_csr.call(attributes))])
        expect(result).to be_a(Ruby::Rego::UndefinedValue)
      end
    end
  end

  # DoS guard: OpenSSL::X509::Request.new stores attribute values as opaque ASN.1 ANY without
  # recursing, but build_request's OpenSSL::ASN1.decode recurses into them eagerly — a deeply-nested
  # attribute value would overflow the C stack uncatchably. build_request pre-scans depth (safe_asn1?,
  # MAX_ASN1_DEPTH) and maps a CSR nested beyond the bound to undefined. This is a deliberate
  # divergence from OPA (which stores the value un-recursed and returns a struct at any depth), traded
  # for not crashing — reachable only by hand-assembled DER no conforming CSR produces. A depth past
  # the bound but below any crash threshold pins the guard: if it were removed this fails as a clean
  # assertion (struct, not undefined) rather than crashing the suite.
  describe "deeply-nested attribute value (DoS guard)" do
    it "is undefined for an attribute value nested beyond the depth bound (OPA returns a struct)" do
      asn1 = OpenSSL::ASN1
      key = OpenSSL::PKey::EC.generate("prime256v1")
      inner = asn1::Integer.new(1)
      2_000.times { inner = asn1::Sequence.new([inner]) }
      attribute = asn1::Sequence.new([asn1::ObjectId.new("1.2.3.4"), asn1::Set.new([inner])])
      subject = asn1.decode(OpenSSL::X509::Name.parse("/CN=t").to_der)
      spki = asn1.decode(key.public_to_der)
      info = asn1::Sequence.new([asn1::Integer.new(0), subject, spki,
                                 asn1::ASN1Data.new([attribute], 0, :CONTEXT_SPECIFIC)])
      signature = key.sign(OpenSSL::Digest.new("SHA256"), info.to_der)
      der = asn1::Sequence.new([info, asn1::Sequence.new([asn1::ObjectId.new("ecdsa-with-SHA256")]),
                                asn1::BitString.new(signature)]).to_der
      pem = "-----BEGIN CERTIFICATE REQUEST-----\n#{[der].pack("m0").scan(/.{1,64}/).join("\n")}\n" \
            "-----END CERTIFICATE REQUEST-----\n"
      result = registry.call("crypto.x509.parse_certificate_request", [Ruby::Rego::StringValue.new(pem)])
      expect(result).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "type handling" do
    it "is undefined for a non-string argument" do
      [42, true, [1], { "a" => 1 }, nil].each do |bad|
        arg = [Ruby::Rego::Value.from_ruby(bad)]
        expect(registry.call("crypto.x509.parse_certificate_request", arg)).to be_a(Ruby::Rego::UndefinedValue)
      end
    end

    it "registers the builtin" do
      expect(registry.registered?("crypto.x509.parse_certificate_request")).to be(true)
    end
  end
end
# rubocop:enable Metrics/BlockLength
