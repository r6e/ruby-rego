# frozen_string_literal: true

require "json"

# crypto.x509.parse_keypair(cert, key) — parse a certificate (chain) plus its matching private key into
# the JSON shape OPA emits (json.Marshal of Go's tls.Certificate). Every expected value is captured
# byte-for-byte from `opa eval` 1.17 (goldens.json) against committed throwaway cert+key pairs spanning
# the key-type / curve / chain / input-format cross-product, plus the validation and malformed edges,
# so the suite measures real OPA compatibility. Each fixture stores its cert, key, and expected value
# together so they can never drift apart.
# rubocop:disable Metrics/BlockLength
RSpec.describe "crypto.x509.parse_keypair" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  fixtures = File.expand_path("../../../fixtures/crypto_keypairs", __dir__)
  goldens = JSON.parse(File.read(File.join(fixtures, "goldens.json")))

  # goldens.json marks an undefined OPA result with this sentinel (JSON cannot represent "absent").
  undef_sentinel = "__undef__"

  resolve = lambda do |registry, cert, key|
    args = [Ruby::Rego::StringValue.new(cert), Ruby::Rego::StringValue.new(key)]
    result = registry.call("crypto.x509.parse_keypair", args)
    result.is_a?(Ruby::Rego::UndefinedValue) ? undef_sentinel : result.to_ruby
  end

  describe "valid keypairs (every field vs OPA)" do
    goldens.fetch("pairs").each do |name, fixture|
      it "matches OPA on the #{name} keypair" do
        expect(resolve.call(registry, fixture.fetch("cert"), fixture.fetch("key")))
          .to eq(fixture.fetch("expected"))
      end
    end
  end

  describe "validation and totality edge cases" do
    goldens.fetch("edges").each do |name, fixture|
      it "matches OPA on the #{name} edge" do
        expect(resolve.call(registry, fixture.fetch("cert"), fixture.fetch("key")))
          .to eq(fixture.fetch("expected"))
      end
    end
  end

  describe "type handling" do
    it "is undefined for a non-string cert or key argument" do
      ok = Ruby::Rego::StringValue.new("x")
      [42, true, [1], { "a" => 1 }, nil].each do |bad|
        arg = Ruby::Rego::Value.from_ruby(bad)
        expect(registry.call("crypto.x509.parse_keypair", [arg, ok])).to be_a(Ruby::Rego::UndefinedValue)
        expect(registry.call("crypto.x509.parse_keypair", [ok, arg])).to be_a(Ruby::Rego::UndefinedValue)
      end
    end

    it "registers the builtin" do
      expect(registry.registered?("crypto.x509.parse_keypair")).to be(true)
    end
  end
end
# rubocop:enable Metrics/BlockLength
