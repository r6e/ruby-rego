# frozen_string_literal: true

require "json"

# crypto.x509.parse_certificates — parse PEM / base64-DER certificates into the JSON shape OPA
# emits (json.Marshal of Go's x509.Certificate plus the injected URIStrings field). Every expected
# value is captured byte-for-byte from `opa eval` 1.17 (goldens.json) against committed throwaway
# certificates spanning the extension/key/SAN/name-constraint/policy cross-product, plus PEM-vs-
# base64 dispatch edges, so the suite measures real OPA compatibility. Edge inputs are stored with
# their expected values in the golden file so the two can never drift apart.
# rubocop:disable Metrics/BlockLength
RSpec.describe "crypto.x509.parse_certificates" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  fixtures = File.expand_path("../../../fixtures/crypto_certs", __dir__)
  goldens = JSON.parse(File.read(File.join(fixtures, "goldens.json")))

  # goldens.json marks an undefined OPA result with this sentinel (JSON cannot represent "absent").
  undef_sentinel = "__undef__"

  resolve = lambda do |registry, string|
    result = registry.call("crypto.x509.parse_certificates", [Ruby::Rego::StringValue.new(string)])
    result.is_a?(Ruby::Rego::UndefinedValue) ? undef_sentinel : result.to_ruby
  end

  describe "certificate fixtures (every field vs OPA)" do
    goldens.fetch("certs").each do |name, expected|
      it "matches OPA on the #{name} certificate" do
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

  describe "type handling" do
    it "is undefined for a non-string argument" do
      [42, true, [1], { "a" => 1 }, nil].each do |bad|
        arg = [Ruby::Rego::Value.from_ruby(bad)]
        expect(registry.call("crypto.x509.parse_certificates", arg)).to be_a(Ruby::Rego::UndefinedValue)
      end
    end

    it "registers the builtin" do
      expect(registry.registered?("crypto.x509.parse_certificates")).to be(true)
    end
  end
end
# rubocop:enable Metrics/BlockLength
