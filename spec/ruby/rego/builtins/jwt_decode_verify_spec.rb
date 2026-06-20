# frozen_string_literal: true

require "base64"
require "json"
require "openssl"

# io.jwt.decode_verify(jwt, constraints) verifies a compact JWS against a key AND standard claim
# constraints, returning [valid, header, payload] (or [false, {}, {}] / undefined). Goldens captured from
# `opa eval` 1.17: every algorithm is deterministic because decode_verify VERIFIES a fixed token. exp/nbf
# goldens pass an explicit `time` (ns) so they never depend on wall-clock.
# rubocop:disable Metrics/BlockLength
RSpec.describe "io.jwt.decode_verify" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  fixtures = File.expand_path("../../../fixtures/jwt_decode_verify", __dir__)
  goldens = JSON.parse(File.read(File.join(fixtures, "goldens.json")))

  def call_dv(jwt, constraints)
    result = registry.call("io.jwt.decode_verify",
                           [Ruby::Rego::StringValue.new(jwt), Ruby::Rego::Value.from_ruby(constraints)])
    result.is_a?(Ruby::Rego::UndefinedValue) ? "__undef__" : result.to_ruby
  end

  def hmac_token(claims, secret: "0123456789abcdef0123456789abcdef")
    header = Base64.urlsafe_encode64(JSON.generate("alg" => "HS256"), padding: false)
    payload = Base64.urlsafe_encode64(JSON.generate(claims), padding: false)
    sig = Base64.urlsafe_encode64(OpenSSL::HMAC.digest("SHA256", secret, "#{header}.#{payload}"), padding: false)
    "#{header}.#{payload}.#{sig}"
  end

  describe "matches OPA across the result taxonomy (goldens)" do
    goldens.each do |name, fixture|
      it "matches OPA on #{name}" do
        expect(call_dv(fixture.fetch("jwt"), fixture.fetch("constraints"))).to eq(fixture.fetch("expected"))
      end
    end
  end

  describe "default time (no `time` constraint uses now)" do
    secret = "0123456789abcdef0123456789abcdef"

    it "accepts an unexpired token and rejects an expired one against the wall clock" do
      now = Time.now.to_i
      expect(call_dv(hmac_token({ "exp" => now + 3600 }), { "secret" => secret })[0]).to be(true)
      expect(call_dv(hmac_token({ "exp" => now - 3600 }), { "secret" => secret })).to eq([false, {}, {}])
    end

    it "honours nbf against the wall clock" do
      now = Time.now.to_i
      expect(call_dv(hmac_token({ "nbf" => now - 3600 }), { "secret" => secret })[0]).to be(true)
      expect(call_dv(hmac_token({ "nbf" => now + 3600 }), { "secret" => secret })).to eq([false, {}, {}])
    end
  end

  # OPA panics on a numeric `iss` claim when an iss constraint is given (ast.Number vs ast.String upstream
  # bug); the gem stays total and returns false — a numeric iss never equals a string constraint.
  describe "numeric iss claim with an iss constraint (OPA upstream-bug divergence)" do
    secret = "0123456789abcdef0123456789abcdef"

    it "returns [false, {}, {}] rather than crashing" do
      expect(call_dv(hmac_token({ "iss" => 5 }), { "secret" => secret, "iss" => "acme" })).to eq([false, {}, {}])
    end

    it "ignores a numeric iss when no iss constraint is given" do
      expect(call_dv(hmac_token({ "iss" => 5 }), { "secret" => secret })[0]).to be(true)
    end
  end

  describe "registration and type handling" do
    it "registers the builtin" do
      expect(registry.registered?("io.jwt.decode_verify")).to be(true)
    end

    it "is undefined for a non-string jwt argument" do
      ok = Ruby::Rego::Value.from_ruby({ "secret" => "x" })
      [42, true, ["a"], { "a" => 1 }, nil].each do |bad|
        result = registry.call("io.jwt.decode_verify", [Ruby::Rego::Value.from_ruby(bad), ok])
        expect(result).to be_a(Ruby::Rego::UndefinedValue)
      end
    end
  end
end
# rubocop:enable Metrics/BlockLength
