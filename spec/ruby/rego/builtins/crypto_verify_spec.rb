# frozen_string_literal: true

require "json"

# crypto.x509.parse_and_verify_certificates(certs) and ...with_options(certs, options) — verify a
# certificate chain and return OPA's [verified, chain] (json.Marshal of Go's tls/x509 Verify result),
# or [false, []] on failure, or undefined for bad options. Every expected value is captured byte-for-
# byte from `opa eval` 1.17 (goldens.json) against committed chains spanning the EKU / signature /
# validity / name-constraint / path-length / input-format cross-product plus the options surface, so
# the suite measures real OPA compatibility. Valid certs use a wide 2000..2100 validity so the
# no-options builtin's time.Now()-based verification stays stable whenever the suite runs.
# rubocop:disable Metrics/BlockLength
RSpec.describe "crypto.x509.parse_and_verify_certificates" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  fixtures = File.expand_path("../../../fixtures/crypto_verify", __dir__)
  goldens = JSON.parse(File.read(File.join(fixtures, "goldens.json")))

  undef_sentinel = "__undef__"

  resolve = lambda do |result|
    result.is_a?(Ruby::Rego::UndefinedValue) ? undef_sentinel : result.to_ruby
  end

  describe "parse_and_verify_certificates (chain verification vs OPA)" do
    goldens.fetch("verify").each do |name, fixture|
      it "matches OPA on the #{name} chain" do
        result = registry.call("crypto.x509.parse_and_verify_certificates",
                               [Ruby::Rego::StringValue.new(fixture.fetch("bundle"))])
        expect(resolve.call(result)).to eq(fixture.fetch("expected"))
      end
    end
  end

  describe "parse_and_verify_certificates_with_options (options + chain vs OPA)" do
    goldens.fetch("options").each do |name, fixture|
      it "matches OPA on the #{name} options case" do
        args = [Ruby::Rego::StringValue.new(fixture.fetch("bundle")),
                Ruby::Rego::Value.from_ruby(fixture.fetch("options"))]
        result = registry.call("crypto.x509.parse_and_verify_certificates_with_options", args)
        expect(resolve.call(result)).to eq(fixture.fetch("expected"))
      end
    end
  end

  describe "type handling" do
    it "is undefined for a non-string certificate argument" do
      [42, true, [1], { "a" => 1 }, nil].each do |bad|
        arg = [Ruby::Rego::Value.from_ruby(bad)]
        expect(registry.call("crypto.x509.parse_and_verify_certificates", arg))
          .to be_a(Ruby::Rego::UndefinedValue)
      end
    end

    it "is undefined for a non-object options argument" do
      ok = Ruby::Rego::StringValue.new("x")
      [42, true, [1], "s", nil].each do |bad|
        arg = [ok, Ruby::Rego::Value.from_ruby(bad)]
        expect(registry.call("crypto.x509.parse_and_verify_certificates_with_options", arg))
          .to be_a(Ruby::Rego::UndefinedValue)
      end
    end

    it "registers both builtins" do
      expect(registry.registered?("crypto.x509.parse_and_verify_certificates")).to be(true)
      expect(registry.registered?("crypto.x509.parse_and_verify_certificates_with_options")).to be(true)
    end
  end
end
# rubocop:enable Metrics/BlockLength
