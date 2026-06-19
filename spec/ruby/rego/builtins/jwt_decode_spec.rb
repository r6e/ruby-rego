# frozen_string_literal: true

require "json"

# io.jwt.decode(jwt) splits a compact JWS "header.payload.signature" into
# [header, payload, signature]: header and payload are the base64url-decoded JSON objects and the
# signature is the lowercase hex of the decoded signature bytes — byte-for-byte OPA's builtinJWTDecode.
# Every expected value in goldens.json was captured from `opa eval` 1.17 over a grammar-spanning case
# set (segment count, header/payload object-ness, base64url alphabet, padding, JSON fidelity, signature
# bytes), so the suite measures real OPA compatibility rather than a re-derivation of the spec.
# rubocop:disable Metrics/BlockLength
RSpec.describe "io.jwt.decode" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  fixtures = File.expand_path("../../../fixtures/jwt_decode", __dir__)
  goldens = JSON.parse(File.read(File.join(fixtures, "goldens.json")))

  undef_sentinel = "__undef__"

  resolve = lambda do |result|
    result.is_a?(Ruby::Rego::UndefinedValue) ? undef_sentinel : result.to_ruby
  end

  describe "compact JWS decoding vs OPA" do
    goldens.fetch("decode").each do |name, fixture|
      it "matches OPA on the #{name} token" do
        result = registry.call("io.jwt.decode", [Ruby::Rego::StringValue.new(fixture.fetch("token"))])
        expect(resolve.call(result)).to eq(fixture.fetch("expected"))
      end
    end
  end

  # A base64url-encoded JWT segment without padding, as io.jwt.decode expects.
  encode_segment = lambda do |bytes|
    [bytes].pack("m0").tr("+/", "-_").delete("=")
  end

  # Builds a single-key object nested `depth` levels deep: {"a":{"a":...1...}}.
  nested_object = lambda do |depth|
    (%({"a":) * depth) << "1" << ("}" * depth)
  end

  describe "totality on deeply nested JSON" do
    header = encode_segment.call('{"alg":"none"}')

    # Go's encoding/json decodes to depth 10000; Ruby's JSON.parse caps at 100, so a deeper payload is
    # undefined here (the safe, gem-stricter direction). The cap also keeps the recursive value builder
    # below the stack limit — raising it would let JSON.parse succeed and then overflow with an
    # uncatchable SystemStackError, aborting evaluation. This pins "undefined, never raises".
    it "is undefined (not a raised error) for a payload nested past Ruby's JSON limit" do
      token = "#{header}.#{encode_segment.call(nested_object.call(5000))}.#{encode_segment.call("sig")}"
      expect { registry.call("io.jwt.decode", [Ruby::Rego::StringValue.new(token)]) }.not_to raise_error
      expect(registry.call("io.jwt.decode", [Ruby::Rego::StringValue.new(token)]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "consistency with json.unmarshal" do
    header = encode_segment.call('{"alg":"none"}')

    # io.jwt.decode parses the header/payload through the same JSON.parse as json.unmarshal, so a decoded
    # payload must equal json.unmarshal of the same bytes (including the gem's invalid-UTF-8 handling,
    # which is a gem-wide divergence from OPA rather than an io.jwt.decode quirk). Bytes are smuggled
    # base64url-encoded so the raw, possibly invalid-UTF-8 input is identical on both paths.
    {
      "raw invalid byte" => %({"k":"\xFF"}).b,
      "valid surrogate pair" => '{"k":"😀"}',
      "lone surrogate" => '{"k":"\uD800"}'
    }.each do |label, payload_bytes|
      it "decodes the payload identically to json.unmarshal for a #{label}" do
        token = "#{header}.#{encode_segment.call(payload_bytes)}.#{encode_segment.call("sig")}"
        decoded = registry.call("io.jwt.decode", [Ruby::Rego::StringValue.new(token)])
        unmarshalled = registry.call("json.unmarshal", [Ruby::Rego::StringValue.new(payload_bytes)])

        if unmarshalled.is_a?(Ruby::Rego::UndefinedValue)
          expect(decoded).to be_a(Ruby::Rego::UndefinedValue)
        else
          expect(decoded.to_ruby[1]).to eq(unmarshalled.to_ruby)
        end
      end
    end
  end

  describe "totality on invalid-encoding tokens" do
    # split / Regexp#match? raise on bytes that are invalid in the string's own (UTF-8) encoding. The
    # registry rescues only BuiltinArgumentError, so such a raise would abort the whole policy; the
    # builtin must map it to undefined instead. OPA returns undefined for the same token.
    it "is undefined (not a raised error) for an invalid-UTF-8 token" do
      bad = "ab.cd.ef\xFF".dup.force_encoding("UTF-8")
      expect { registry.call("io.jwt.decode", [Ruby::Rego::StringValue.new(bad)]) }.not_to raise_error
      expect(registry.call("io.jwt.decode", [Ruby::Rego::StringValue.new(bad)]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    # UTF-16/UTF-32 are valid_encoding? == true but ASCII-incompatible, so split(".")/match? against an
    # ASCII literal raise Encoding::CompatibilityError — also not a BuiltinArgumentError. The guard must
    # reject by ascii-compatibility, not just validity.
    %w[UTF-16LE UTF-16BE UTF-32LE].each do |enc|
      it "is undefined (not a raised error) for a #{enc} token" do
        token = "abc.def.ghi".encode(enc)
        expect { registry.call("io.jwt.decode", [Ruby::Rego::StringValue.new(token)]) }.not_to raise_error
        expect(registry.call("io.jwt.decode", [Ruby::Rego::StringValue.new(token)]))
          .to be_a(Ruby::Rego::UndefinedValue)
      end
    end
  end

  describe "non-canonical base64url (gem-more-strict, crafted input only)" do
    # Ruby's strict base64url decode rejects a final character carrying non-zero unused bits (here the
    # signature "AB"), where Go masks them and decodes (to "00"). Canonical encoders never emit such a
    # segment, so real tokens are unaffected; this pins the safe, gem-stricter direction (the gem is
    # undefined where OPA decodes — never the reverse).
    it "is undefined for a segment with non-canonical trailing bits" do
      expect(registry.call("io.jwt.decode", [Ruby::Rego::StringValue.new("e30.e30.AB")]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "type handling" do
    it "is undefined for a non-string token argument" do
      [42, 3.14, true, false, [1], { "a" => 1 }, nil].each do |bad|
        arg = [Ruby::Rego::Value.from_ruby(bad)]
        expect(registry.call("io.jwt.decode", arg)).to be_a(Ruby::Rego::UndefinedValue)
      end
    end

    it "registers the builtin" do
      expect(registry.registered?("io.jwt.decode")).to be(true)
    end
  end
end
# rubocop:enable Metrics/BlockLength
