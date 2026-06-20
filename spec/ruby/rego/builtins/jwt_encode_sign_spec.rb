# frozen_string_literal: true

require "base64"
require "json"
require "openssl"

# io.jwt.encode_sign(headers, payload, key) and io.jwt.encode_sign_raw(headers, payload, key) build a signed
# compact JWS. Goldens captured from `opa eval` 1.17: deterministic algorithms (HS*/RS*/EdDSA) are pinned
# byte-for-byte; randomized algorithms (ES*/PS*) are exercised by round-trip — the gem's token must verify
# (via the io.jwt.verify_* builtins), and an OPA-produced token must verify in the gem too. Error cases pin
# the undefined outcomes (unsupported/absent alg, non-JSON header/payload/key, alg-key mismatch, no private
# key).
# rubocop:disable Metrics/BlockLength
RSpec.describe "io.jwt.encode_sign / encode_sign_raw" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  fixtures = File.expand_path("../../../fixtures/jwt_encode_sign", __dir__)
  goldens = JSON.parse(File.read(File.join(fixtures, "goldens.json")))

  undef_sentinel = "__undef__"

  def call_builtin(builtin, *args)
    values = args.map { |a| a.is_a?(String) ? Ruby::Rego::StringValue.new(a) : Ruby::Rego::Value.from_ruby(a) }
    result = registry.call(builtin, values)
    result.is_a?(Ruby::Rego::UndefinedValue) ? "__undef__" : result.to_ruby
  end

  describe "deterministic output vs OPA (byte-for-byte)" do
    goldens.fetch("deterministic").each do |name, fixture|
      it "matches OPA on #{name}" do
        out = call_builtin(fixture.fetch("fn"), fixture.fetch("headers"), fixture.fetch("payload"),
                           fixture.fetch("key"))
        expect(out).to eq(fixture.fetch("expected"))
      end
    end
  end

  describe "round-trip for randomized and deterministic algorithms" do
    goldens.fetch("roundtrip").each do |name, fixture|
      it "produces a token that verifies, and verifies OPA's token, for #{name}" do
        token = call_builtin("io.jwt.encode_sign_raw", fixture.fetch("headers"), fixture.fetch("payload"),
                             fixture.fetch("sign_key"))
        expect(token).not_to eq(undef_sentinel)
        expect(call_builtin(fixture.fetch("verify_fn"), token, fixture.fetch("verify_key"))).to be(true)
        expect(call_builtin(fixture.fetch("verify_fn"), fixture.fetch("opa_token"),
                            fixture.fetch("verify_key"))).to be(true)
      end
    end
  end

  describe "error outcomes vs OPA" do
    goldens.fetch("errors").each do |name, fixture|
      it "is undefined on #{name}" do
        out = call_builtin(fixture.fetch("fn"), fixture.fetch("headers"), fixture.fetch("payload"),
                           fixture.fetch("key"))
        expect(out).to eq(fixture.fetch("expected"))
      end
    end
  end

  # A header may repeat `alg`; OPA/Go select the FIRST occurrence while Ruby's JSON.parse keeps the last,
  # so the gem extracts the first top-level `alg` itself (see Jwt.first_alg). These pin that semantics,
  # including that a nested `alg` at a deeper depth is ignored (exercises the value-skipping scanner).
  describe "duplicate alg header (OPA first-occurrence wins)" do
    secret = "0123456789abcdef0123456789abcdef"
    oct_key = JSON.generate("kty" => "oct", "k" => Base64.urlsafe_encode64(secret, padding: false))
    payload = '{"x":1}'

    it "signs with the first alg when a later alg differs" do
      token = call_builtin("io.jwt.encode_sign_raw", '{"alg":"HS256","alg":"none"}', payload, oct_key)
      expect(token).not_to eq(undef_sentinel)
      expect(call_builtin("io.jwt.verify_hs256", token, secret)).to be(true)
    end

    it "is undefined when the first alg is unsupported (none), ignoring a later valid alg" do
      expect(call_builtin("io.jwt.encode_sign_raw", '{"alg":"none","alg":"HS256"}', payload, oct_key))
        .to eq(undef_sentinel)
    end

    it "uses the first top-level alg and ignores a nested alg" do
      token = call_builtin("io.jwt.encode_sign_raw", '{"h":{"alg":"none"},"alg":"HS256"}', payload, oct_key)
      expect(token).not_to eq(undef_sentinel)
      expect(call_builtin("io.jwt.verify_hs256", token, secret)).to be(true)
    end
  end

  # Ruby's json gem accepts // and /* */ comments; Go (OPA) rejects them, so encode_sign_raw must too —
  # otherwise the gem emits a SIGNED token OPA refuses (gem-more-lenient). A comment inside a string
  # VALUE is legal JSON and must still sign (matches OPA byte-for-byte).
  describe "JSON comment leniency (gem must reject like OPA)" do
    secret = "0123456789abcdef0123456789abcdef"
    k_b64 = Base64.urlsafe_encode64(secret, padding: false)
    oct_key = %({"kty":"oct","k":"#{k_b64}"})
    oct_key_comment = %({"kty":"oct","k":"#{k_b64}"/*c*/})
    payload = '{"sub":"42"}'
    header = '{"alg":"HS256"}'

    {
      "line comment in header" => ['{"alg":"HS256"}//x', payload, oct_key],
      "block comment in header" => ['{"alg":"HS256","x":1/*c*/}', payload, oct_key],
      "block comment in payload" => [header, '{"sub":"42"/*c*/}', oct_key],
      "block comment in key" => [header, payload, oct_key_comment]
    }.each do |label, (hdr, pay, key)|
      it "is undefined for a #{label}" do
        expect(call_builtin("io.jwt.encode_sign_raw", hdr, pay, key)).to eq(undef_sentinel)
      end
    end

    it "still signs when a comment-like sequence appears inside a string value" do
      token = call_builtin("io.jwt.encode_sign_raw", header, '{"u":"http://a/b","n":"/* x */"}', oct_key)
      expect(token).not_to eq(undef_sentinel)
      expect(call_builtin("io.jwt.verify_hs256", token, secret)).to be(true)
    end
  end

  # A non-ascii-compatible (UTF-16) or invalid-UTF-8 argument would make the JSON scanners' StringScanner
  # raise Encoding::CompatibilityError / ArgumentError — not JSON::ParserError — and escape the registry's
  # totality boundary. The encoding guard in strict_json_parse maps them to undefined (mirrors io.jwt.decode).
  describe "argument encoding (totality)" do
    secret = "0123456789abcdef0123456789abcdef"
    oct_key = %({"kty":"oct","k":"#{Base64.urlsafe_encode64(secret, padding: false)}"})
    header = '{"alg":"HS256"}'
    payload = '{"sub":"42"}'

    {
      "UTF-16 header" => [header.encode("UTF-16LE"), payload, oct_key],
      "UTF-16 payload" => [header, payload.encode("UTF-16LE"), oct_key],
      "UTF-16 key" => [header, payload, oct_key.encode("UTF-16LE")],
      "invalid-UTF-8 header" => ["#{header}\xff".force_encoding("UTF-8"), payload, oct_key]
    }.each do |label, (hdr, pay, key)|
      it "is undefined (no raise) for a #{label}" do
        expect { @result = call_builtin("io.jwt.encode_sign_raw", hdr, pay, key) }.not_to raise_error
        expect(@result).to eq(undef_sentinel)
      end
    end

    it "is undefined (no raise) for an encode_sign object key with a non-ascii-compatible component" do
      key = { "kty" => "oct", "k" => Base64.urlsafe_encode64(secret, padding: false).encode("UTF-16LE") }
      expect { @result = call_builtin("io.jwt.encode_sign", { "alg" => "HS256" }, { "x" => 1 }, key) }
        .not_to raise_error
      expect(@result).to eq(undef_sentinel)
    end
  end

  # OPA runs Go's rsa.Validate -> checkPub, which bounds the public exponent to 2 <= e <= 2^31-1.
  # OpenSSL signs with any e (including e=1, the identity), so without this check the gem would emit a
  # signed token OPA refuses. Both cases confirmed undefined on OPA 1.17 (40/40 race-hardened reads).
  describe "RSA public-exponent bounds (Go checkPub)" do
    # Encode an integer (or OpenSSL::BN) as big-endian JWK bytes — BN#to_s(2) gives the byte string,
    # whereas Integer#to_s(2) would give a binary-DIGIT string ("1" not "\x01"), encoding the wrong value.
    b64u = ->(int) { Base64.urlsafe_encode64(OpenSSL::BN.new(int.to_i).to_s(2), padding: false) }
    rsa = OpenSSL::PKey::RSA.generate(2048)
    base = { "kty" => "RSA", "n" => b64u[rsa.n], "p" => b64u[rsa.p], "q" => b64u[rsa.q] }
    header = '{"alg":"RS256"}'
    payload = '{"sub":"42"}'

    it "is undefined for e=1, d=1 (below Go's minimum of 2)" do
      key = JSON.generate(base.merge("e" => b64u[1], "d" => b64u[1]))
      expect(call_builtin("io.jwt.encode_sign_raw", header, payload, key)).to eq(undef_sentinel)
    end

    it "is undefined for e > 2^31-1 (above Go's maximum)" do
      lambda_n = (rsa.p.to_i - 1) * (rsa.q.to_i - 1) / (rsa.p.to_i - 1).gcd(rsa.q.to_i - 1)
      # smallest odd e just above the max that is coprime to lambda (so big_d exists and the key is
      # otherwise consistent — only RSA_MAX_EXPONENT rejects it). Deterministic; never skips.
      big_e = (2**31) + 1
      big_e += 2 until big_e.gcd(lambda_n) == 1
      big_d = OpenSSL::BN.new(big_e.to_s).mod_inverse(OpenSSL::BN.new(lambda_n.to_s))
      key = JSON.generate(base.merge("e" => b64u[big_e], "d" => b64u[big_d.to_i]))
      expect(call_builtin("io.jwt.encode_sign_raw", header, payload, key)).to eq(undef_sentinel)
    end

    # An even e can never have a consistent d (no inverse exists mod the even p-1/q-1), so this is
    # rejected by both valid_exponent?'s odd? clause and the e*d≡1 consistency check — it pins the
    # outcome (undefined, matching OPA), not the odd? clause in isolation.
    it "is undefined for an even exponent" do
      key = JSON.generate(base.merge("e" => b64u[4], "d" => b64u[rsa.d]))
      expect(call_builtin("io.jwt.encode_sign_raw", header, payload, key)).to eq(undef_sentinel)
    end

    it "still signs with a normal exponent (e=65537)" do
      key = JSON.generate(base.merge("e" => b64u[rsa.e], "d" => b64u[rsa.d]))
      token = call_builtin("io.jwt.encode_sign_raw", header, payload, key)
      expect(token).not_to eq(undef_sentinel)
      expect(call_builtin("io.jwt.verify_rs256", token, rsa.public_key.to_pem)).to be(true)
    end
  end

  # OPA (like the gem) does NOT validate an EC private JWK's x/y against d — a token signs from d alone,
  # so a mismatched-but-on-curve x/y still signs (both sides), while an OFF-curve point is rejected by
  # OpenSSL's DER load (and by OPA). Pins these confirmed cells of the key-validation grammar.
  describe "EC x/y coordinates (not checked against d, matching OPA)" do
    ec = OpenSSL::PKey::EC.generate("prime256v1")
    width = 32
    b64u = ->(bytes) { Base64.urlsafe_encode64(bytes, padding: false) }
    base = { "kty" => "EC", "crv" => "P-256", "d" => b64u[ec.private_key.to_s(2).rjust(width, "\x00".b)] }

    it "signs with a mismatched but on-curve x/y (from another key)" do
      other = OpenSSL::PKey::EC.generate("prime256v1").public_key.to_bn(:uncompressed).to_s(2)
      key = JSON.generate(base.merge("x" => b64u[other[1, width]], "y" => b64u[other[1 + width, width]]))
      token = call_builtin("io.jwt.encode_sign_raw", '{"alg":"ES256"}', '{"sub":"42"}', key)
      expect(token).not_to eq(undef_sentinel)
    end

    it "is undefined for an off-curve x/y" do
      key = JSON.generate(base.merge("x" => b64u["\x11".b * width], "y" => b64u["\x22".b * width]))
      expect(call_builtin("io.jwt.encode_sign_raw", '{"alg":"ES256"}', '{"sub":"42"}', key)).to eq(undef_sentinel)
    end
  end

  describe "registration and type handling" do
    it "registers both encode builtins" do
      expect(registry.registered?("io.jwt.encode_sign")).to be(true)
      expect(registry.registered?("io.jwt.encode_sign_raw")).to be(true)
    end

    it "is undefined for non-string encode_sign_raw arguments" do
      ok = Ruby::Rego::StringValue.new('{"alg":"HS256"}')
      [42, true, [1], { "a" => 1 }, nil].each do |bad|
        bad_value = Ruby::Rego::Value.from_ruby(bad)
        expect(registry.call("io.jwt.encode_sign_raw", [bad_value, ok, ok])).to be_a(Ruby::Rego::UndefinedValue)
      end
    end
  end
end
# rubocop:enable Metrics/BlockLength
