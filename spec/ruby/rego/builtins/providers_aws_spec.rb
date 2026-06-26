# frozen_string_literal: true

require "json"

# providers.aws.sign_req(request, aws_config, time_ns) — a faithful port of OPA's AWS Signature V4
# signer (internal/providers/aws/signing_v4.go). The signed request (and especially the Authorization
# signature) is byte-exact with OPA; all goldens are captured from `opa eval` 1.17.1, plus the
# canonical AWS docs "GET Object" example. OPA's SigV4 deviates from the AWS spec in three
# byte-affecting ways the port reproduces: the canonical query is RawQuery verbatim (not sorted), header
# values are signed un-trimmed, and the canonical URI is url.EscapedPath() (user %-encoding preserved).
# rubocop:disable Metrics/BlockLength
RSpec.describe "providers.aws.sign_req" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  fixtures = File.expand_path("../../../fixtures/providers", __dir__)
  goldens = JSON.parse(File.read(File.join(fixtures, "aws_sign_req_goldens.json")))

  def sign(request, config, time_ns)
    result = registry.call("providers.aws.sign_req", [request, config, time_ns])
    result.is_a?(Ruby::Rego::UndefinedValue) ? :undef : result.to_ruby
  end

  describe "matches OPA (byte-exact signed request)" do
    goldens.each do |name, fixture|
      it "agrees with OPA on #{name}" do
        expect(sign(fixture.fetch("req"), fixture.fetch("cfg"), fixture.fetch("t"))).to eq(fixture.fetch("signed"))
      end
    end
  end

  # The canonical AWS SigV4 "GET Object" example signature, the documented reference vector.
  it "produces the canonical AWS docs example signature" do
    out = sign(
      { "method" => "GET", "url" => "https://examplebucket.s3.amazonaws.com/test.txt",
        "headers" => { "Range" => "bytes=0-9" } },
      { "aws_access_key" => "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key" => "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_service" => "s3", "aws_region" => "us-east-1" },
      1_369_353_600_000_000_000
    )
    expect(out["headers"]["Authorization"]).to include(
      "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    )
  end

  config = lambda do |extra = {}|
    { "aws_access_key" => "AK", "aws_secret_access_key" => "SK", "aws_service" => "s3",
      "aws_region" => "us-east-1" }.merge(extra)
  end
  base = "https://ex.s3.amazonaws.com"

  describe "OPA-specific SigV4 quirks" do
    # x-amz-content-sha256 is emitted only for s3/glacier; UNSIGNED-PAYLOAD when disable_payload_signing.
    it "emits x-amz-content-sha256 only for s3/glacier" do
      s3 = sign({ "method" => "GET", "url" => "#{base}/p" }, config.call, 0)
      api = sign({ "method" => "GET", "url" => "#{base}/p" }, config.call("aws_service" => "execute-api"), 0)
      expect(s3["headers"]).to have_key("x-amz-content-sha256")
      expect(api["headers"]).not_to have_key("x-amz-content-sha256")
    end

    it "uses UNSIGNED-PAYLOAD when disable_payload_signing (config key)" do
      out = sign({ "method" => "GET", "url" => "#{base}/p" }, config.call("disable_payload_signing" => true), 0)
      expect(out["headers"]["x-amz-content-sha256"]).to eq("UNSIGNED-PAYLOAD")
    end

    it "hashes raw_body over body, and a non-string raw_body as empty" do
      empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      raw = sign({ "method" => "POST", "url" => "#{base}/p", "raw_body" => "", "body" => { "a" => 1 } }, config.call, 0)
      expect(raw["headers"]["x-amz-content-sha256"]).to eq(empty) # raw_body "" wins over body
      # a non-string raw_body is treated as "" (matching getReqBodyBytes), still winning over body
      nonstring = sign({ "method" => "POST", "url" => "#{base}/p", "raw_body" => 123, "body" => { "a" => 1 } },
                       config.call, 0)
      expect(nonstring["headers"]["x-amz-content-sha256"]).to eq(empty)
    end

    # With the arbitrary-precision number model, json.marshal of a body number written as a Rego literal
    # is byte-exact with OPA (1.50 stays 1.50, 1e10 stays 1e10), so the signed payload hash and signature
    # match OPA — verified against `opa eval` 1.17. (A body number arriving from parsed JSON input still
    # collapses through Float, the deferred input-precision gap, so exact-byte callers use raw_body.)
    it "hashes an object body with literal non-integer numbers byte-exact with OPA" do
      body = { "x" => Ruby::Rego::Number.literal("1.50"), "y" => Ruby::Rego::Number.literal("1e10"), "z" => 2 }
      out = sign(
        { "method" => "POST", "url" => "https://example.s3.amazonaws.com/o", "headers" => {}, "body" => body },
        { "aws_access_key" => "AKIDEXAMPLE", "aws_secret_access_key" => "secret",
          "aws_service" => "s3", "aws_region" => "us-east-1" },
        1_369_353_600_000_000_000
      )
      expect(out["headers"]["x-amz-content-sha256"])
        .to eq("5ae8aa602c5448e562661d09da2c5a4ac60c0a1261212cc57df1b570e9ba24c9")
      expect(out["headers"]["Authorization"])
        .to end_with("Signature=2c34ae26aca2683e4c98a8bc88d3bea759e1ed062559a4ae3f6c95dc2bc2c219")
    end

    it "preserves the host port and keeps a user Host alongside the signing host" do
      out = sign({ "method" => "GET", "url" => "https://ex.s3.amazonaws.com:8443/p", "headers" => { "Host" => "u" } },
                 config.call, 0)
      expect(out["headers"]["host"]).to eq("ex.s3.amazonaws.com:8443")
      expect(out["headers"]["Host"]).to eq("u")
    end

    it "adds x-amz-security-token only when a session token is present" do
      with = sign({ "method" => "GET", "url" => "#{base}/p" }, config.call("aws_session_token" => "T"), 0)
      without = sign({ "method" => "GET", "url" => "#{base}/p" }, config.call, 0)
      expect(with["headers"]["x-amz-security-token"]).to eq("T")
      expect(without["headers"]).not_to have_key("x-amz-security-token")
    end
  end

  describe "undefined boundary (every precondition failure is undefined)" do
    good_cfg = { "aws_access_key" => "AK", "aws_secret_access_key" => "SK", "aws_service" => "s3",
                 "aws_region" => "us-east-1" }
    good_req = { "method" => "GET", "url" => "https://ex.s3.amazonaws.com/p" }

    it "is undefined for a non-object request or config" do
      expect(sign("x", good_cfg, 0)).to eq(:undef)
      expect(sign(good_req, "x", 0)).to eq(:undef)
    end

    it "is undefined for a missing/non-string method or url, or an unparseable url" do
      expect(sign({ "url" => "https://h/p" }, good_cfg, 0)).to eq(:undef)
      expect(sign({ "method" => 1, "url" => "https://h/p" }, good_cfg, 0)).to eq(:undef)
      expect(sign({ "method" => "GET", "url" => "h ttp://x" }, good_cfg, 0)).to eq(:undef)
    end

    it "is undefined for a request key outside http.send's allowed set" do
      expect(sign(good_req.merge("junk" => 1), good_cfg, 0)).to eq(:undef)
      # disable_payload_signing is a CONFIG key, not a request key
      expect(sign(good_req.merge("disable_payload_signing" => true), good_cfg, 0)).to eq(:undef)
    end

    it "is undefined for a config missing a required key or holding a non-string one (empty strings are ok)" do
      expect(sign(good_req, { "aws_access_key" => "a" }, 0)).to eq(:undef)
      expect(sign(good_req, good_cfg.merge("aws_region" => 5), 0)).to eq(:undef)
      expect(sign(good_req, good_cfg.merge("aws_region" => ""), 0)).not_to eq(:undef)
    end

    it "is undefined for a non-integer or int64-overflowing time_ns, or a non-boolean disable_payload_signing" do
      expect(sign(good_req, good_cfg, 1.5)).to eq(:undef)
      expect(sign(good_req, good_cfg, 2**63)).to eq(:undef)
      expect(sign(good_req, good_cfg, -(2**63) - 1)).to eq(:undef)
      expect(sign(good_req, good_cfg.merge("disable_payload_signing" => "yes"), 0)).to eq(:undef)
    end

    # An invalid-UTF-8 url or header key would make Uri::Parser.parse / String#downcase raise a bare
    # ArgumentError that escapes the registry's BuiltinArgumentError rescue and aborts the whole policy;
    # the encodable? guard maps it to undefined instead (a documented divergence — OPA signs).
    it "is undefined (never raises) for an invalid-UTF-8 url or header key" do
      bad = (+"\xED\xB2\xAE").force_encoding("UTF-8") # a lone surrogate, invalid UTF-8
      expect { sign({ "method" => "GET", "url" => bad }, good_cfg, 0) }.not_to raise_error
      expect(sign({ "method" => "GET", "url" => bad }, good_cfg, 0)).to eq(:undef)
      expect(sign({ "method" => "GET", "url" => "https://h/p", "headers" => { bad => "v" } }, good_cfg,
                  0)).to eq(:undef)
      # a BINARY string (ascii-compatible, valid) still signs
      binary = (+"\xFF").force_encoding("ASCII-8BIT")
      expect(sign({ "method" => "GET", "url" => "https://h/p", "headers" => { binary => "v" } }, good_cfg,
                  0)).not_to eq(:undef)
    end

    # SigV4 signs bytes: two attacker strings of INCOMPATIBLE Ruby encodings (a valid UTF-8 one and an
    # ASCII-8BIT one, both individually fine) must not raise Encoding::CompatibilityError when joined into
    # the canonical request / scope / credential — that would escape the registry rescue and abort the
    # policy. The signer force-encodes signing strings to bytes, so these sign rather than crash.
    it "never raises on two incompatibly-encoded signing strings (header keys/values, config)" do
      utf8 = "xé"
      binary = (+"y\xFF").force_encoding("ASCII-8BIT")
      u = "https://h/p"
      expect do
        sign({ "method" => "GET", "url" => u, "headers" => { utf8 => "a", binary => "b" } }, good_cfg, 0)
        sign({ "method" => "GET", "url" => u, "headers" => { "X-A" => "é", "X-B" => binary } }, good_cfg, 0)
        sign({ "method" => "GET", "url" => u }, good_cfg.merge("aws_service" => utf8, "aws_region" => binary), 0)
      end.not_to raise_error
    end
  end

  # Documented divergence: a `body` (object) is hashed via json.marshal, which uses Ruby's Float#to_s
  # number model, so a body number whose original text carries trailing zeros / scientific notation
  # (1.50, 1e10) hashes differently than OPA (which marshals json.Number's original text). This is the
  # gem-wide json.marshal number divergence; real AWS callers pass raw_body (exact bytes), unaffected.
  it "inherits json.marshal's number model for an object body (documented divergence)" do
    out = sign({ "method" => "POST", "url" => "#{base}/p", "body" => { "x" => 1.5 } }, config.call, 0)
    expect(out["headers"]).to have_key("x-amz-content-sha256") # integer/exact floats agree with OPA
  end
end
# rubocop:enable Metrics/BlockLength
