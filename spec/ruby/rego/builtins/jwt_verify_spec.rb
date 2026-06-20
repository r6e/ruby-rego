# frozen_string_literal: true

require "json"

# io.jwt.verify_{hs,rs,ps,es}{256,384,512} and io.jwt.verify_eddsa verify a compact JWS signature against
# a key, returning a boolean (or undefined for a structurally invalid token / unparseable key). Every
# expected value in goldens.json was captured from `opa eval` 1.17 over the algorithm × key-format ×
# taxonomy matrix — each of the 13 builtins with a correct and a wrong key; PEM public key, PEM
# certificate, JWK, and JWK Set forms; cross-algorithm and wrong-key-type cases; and the structural
# taxonomy (≠3 segments, non-base64url signature, empty/malformed key) — so the suite measures real OPA
# compatibility. Tokens are committed verbatim, so the goldens are stable without re-running OpenSSL.
# rubocop:disable Metrics/BlockLength
RSpec.describe "io.jwt.verify_*" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  fixtures = File.expand_path("../../../fixtures/jwt_verify", __dir__)
  goldens = JSON.parse(File.read(File.join(fixtures, "goldens.json")))

  undef_sentinel = "__undef__"

  resolve = lambda do |result|
    result.is_a?(Ruby::Rego::UndefinedValue) ? undef_sentinel : result.to_ruby
  end

  describe "signature verification vs OPA" do
    goldens.each do |name, fixture|
      it "matches OPA on the #{name} case" do
        args = [Ruby::Rego::StringValue.new(fixture.fetch("jwt")),
                Ruby::Rego::StringValue.new(fixture.fetch("key"))]
        expect(resolve.call(registry.call(fixture.fetch("fn"), args))).to eq(fixture.fetch("expected"))
      end
    end
  end

  describe "registration and type handling" do
    it "registers all thirteen verify builtins" do
      %w[hs256 hs384 hs512 rs256 rs384 rs512 ps256 ps384 ps512 es256 es384 es512 eddsa].each do |alg|
        expect(registry.registered?("io.jwt.verify_#{alg}")).to be(true)
      end
    end

    it "is undefined for non-string arguments" do
      ok = Ruby::Rego::StringValue.new("x")
      [42, true, [1], { "a" => 1 }, nil].each do |bad|
        bad_value = Ruby::Rego::Value.from_ruby(bad)
        expect(registry.call("io.jwt.verify_hs256", [bad_value, ok])).to be_a(Ruby::Rego::UndefinedValue)
        expect(registry.call("io.jwt.verify_rs256", [ok, bad_value])).to be_a(Ruby::Rego::UndefinedValue)
      end
    end
  end
end
# rubocop:enable Metrics/BlockLength
