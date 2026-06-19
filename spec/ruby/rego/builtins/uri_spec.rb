# frozen_string_literal: true

# uri.parse / uri.is_valid — a faithful port of Go's net/url.Parse. All expected values verified
# byte-for-byte against `opa eval` 1.17 (OPA's builtins are thin wrappers over net/url.Parse).
# rubocop:disable Metrics/BlockLength
RSpec.describe "uri builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  def parse(uri)
    result = registry.call("uri.parse", [Ruby::Rego::StringValue.new(uri)])
    result.is_a?(Ruby::Rego::UndefinedValue) ? :undef : result.to_ruby
  end

  def valid?(uri)
    registry.call("uri.is_valid", [Ruby::Rego::StringValue.new(uri)]).to_ruby
  end

  # [uri, expected_parse_object_or_nil, expected_is_valid]
  [
    ["http://h", { "hostname" => "h", "scheme" => "http" }, true],
    ["HTTP://H", { "hostname" => "H", "scheme" => "http" }, true],
    ["a+b-c.d://h", { "hostname" => "h", "scheme" => "a+b-c.d" }, true],
    ["1abc://h", nil, false],
    ["://h", nil, false],
    ["foo:", { "scheme" => "foo" }, true],
    ["foo:bar", { "scheme" => "foo" }, true],
    ["a:b/c", { "scheme" => "a" }, true],
    ["http://host.example.com", { "hostname" => "host.example.com", "scheme" => "http" }, true],
    ["http://h:8080", { "hostname" => "h", "port" => "8080", "scheme" => "http" }, true],
    ["http://h:", { "hostname" => "h", "scheme" => "http" }, true],
    ["http://h:0", { "hostname" => "h", "port" => "0", "scheme" => "http" }, true],
    ["http://h:99999", { "hostname" => "h", "port" => "99999", "scheme" => "http" }, true],
    ["http://h:abc", nil, false],
    ["http://:8080", { "port" => "8080", "scheme" => "http" }, true],
    ["http://h:80:90", { "hostname" => "h:80", "port" => "90", "scheme" => "http" }, true],
    ["http://user@h", { "hostname" => "h", "scheme" => "http" }, true],
    ["http://user:pw@h", { "hostname" => "h", "scheme" => "http" }, true],
    ["http://u:p@h:1/x",
     { "hostname" => "h", "path" => "/x", "port" => "1", "raw_path" => "/x", "scheme" => "http" }, true],
    ["http://", { "scheme" => "http" }, true],
    ["http:///p", { "path" => "/p", "raw_path" => "/p", "scheme" => "http" }, true],
    ["//h/p", { "hostname" => "h", "path" => "/p", "raw_path" => "/p" }, true],
    ["//h", { "hostname" => "h" }, true],
    ["//user@/p", { "path" => "/p", "raw_path" => "/p" }, true],
    ["http://[::1]", { "hostname" => "::1", "scheme" => "http" }, true],
    ["http://[::1]:80", { "hostname" => "::1", "port" => "80", "scheme" => "http" }, true],
    ["http://[fe80::1%25en0]", { "hostname" => "fe80::1%en0", "scheme" => "http" }, true],
    # IPv4-mapped IPv6 ([::ffff:…]) is accepted — Go validates via netip.ParseAddr + !Is4(),
    # which keeps 4-in-6 literals (only Is4() bare-IPv4 is excluded). Pins the IPAddr#ipv6? port.
    ["https://[::ffff:192.0.2.1]:8443/p",
     { "hostname" => "::ffff:192.0.2.1", "path" => "/p", "port" => "8443", "raw_path" => "/p",
       "scheme" => "https" }, true],
    # A raw byte smuggled into the IPv6 literal via %FF must reject, not crash the parser
    # (regression pin for the IPAddr ArgumentError DoS — `rescue ArgumentError` in valid_ipv6?).
    ["http://[%FF::1]/", nil, false],
    # A present-but-empty RFC 6874 zone (%25 then nothing) is rejected — Go 1.26 netip.ParseAddr
    # requires a non-empty zone (OPA 1.17 returns undefined / is_valid false).
    ["http://[fe80::1%25]", nil, false],
    ["http://[fe80::1%25en0]", { "hostname" => "fe80::1%en0", "scheme" => "http" }, true],
    ["http://[::1", nil, false],
    ["http://[::1]:bad", nil, false],
    ["http://h/a/b/c", { "hostname" => "h", "path" => "/a/b/c", "raw_path" => "/a/b/c", "scheme" => "http" }, true],
    ["http://h/a%20b", { "hostname" => "h", "path" => "/a b", "raw_path" => "/a b", "scheme" => "http" }, true],
    ["http://h/a+b", { "hostname" => "h", "path" => "/a+b", "raw_path" => "/a+b", "scheme" => "http" }, true],
    ["http://h/%2e%2e", { "hostname" => "h", "path" => "/..", "raw_path" => "/%2e%2e", "scheme" => "http" }, true],
    ["http://h/%2Fx", { "hostname" => "h", "path" => "//x", "raw_path" => "/%2Fx", "scheme" => "http" }, true],
    ["http://h/%E2%82%AC", { "hostname" => "h", "path" => "/€", "raw_path" => "/€", "scheme" => "http" }, true],
    ["http://h/caf%C3%A9", { "hostname" => "h", "path" => "/café", "raw_path" => "/café", "scheme" => "http" }, true],
    ["http://h/bad%2", nil, false],
    ["http://h/bad%zz", nil, false],
    ["http://h/%", nil, false],
    ["http://h/%41", { "hostname" => "h", "path" => "/A", "raw_path" => "/%41", "scheme" => "http" }, true],
    ["/just/path", { "path" => "/just/path", "raw_path" => "/just/path" }, true],
    ["rel/path", { "path" => "rel/path", "raw_path" => "rel/path" }, true],
    ["foo/bar", { "path" => "foo/bar", "raw_path" => "foo/bar" }, true],
    ["./a", { "path" => "./a", "raw_path" => "./a" }, true],
    ["../a", { "path" => "../a", "raw_path" => "../a" }, true],
    ["http://h/p?a=1&b=2",
     { "hostname" => "h", "path" => "/p", "raw_path" => "/p", "raw_query" => "a=1&b=2", "scheme" => "http" }, true],
    ["http://h?q", { "hostname" => "h", "raw_query" => "q", "scheme" => "http" }, true],
    ["http://h?", { "hostname" => "h", "scheme" => "http" }, true],
    ["http://h/p#frag",
     { "fragment" => "frag", "hostname" => "h", "path" => "/p", "raw_path" => "/p", "scheme" => "http" }, true],
    ["http://h/p#f?q",
     { "fragment" => "f?q", "hostname" => "h", "path" => "/p", "raw_path" => "/p", "scheme" => "http" }, true],
    ["?onlyq", { "raw_query" => "onlyq" }, true],
    ["#onlyf", { "fragment" => "onlyf" }, true],
    ["http://h/p?q#f",
     { "fragment" => "f", "hostname" => "h", "path" => "/p", "raw_path" => "/p",
       "raw_query" => "q", "scheme" => "http" }, true],
    ["http://h/p?%20=%26#%2e",
     { "fragment" => ".", "hostname" => "h", "path" => "/p", "raw_path" => "/p",
       "raw_query" => "%20=%26", "scheme" => "http" }, true],
    ["opaque:x?q#f", { "fragment" => "f", "raw_query" => "q", "scheme" => "opaque" }, true],
    ["mailto:a@b.com", { "scheme" => "mailto" }, true],
    # "scheme:/path" with no authority (Go's OmitHost branch).
    ["file:/etc/hosts", { "path" => "/etc/hosts", "raw_path" => "/etc/hosts", "scheme" => "file" }, true],
    ["urn:isbn:0451450523", { "scheme" => "urn" }, true],
    ["tel:+1-555", { "scheme" => "tel" }, true],
    ["a:b:c", { "scheme" => "a" }, true],
    ["rel:ative/x", { "scheme" => "rel" }, true],
    ["cache_object:foo/bar", nil, false],
    ["", {}, false],
    ["*", { "path" => "*", "raw_path" => "*" }, true],
    ["1http://x", nil, false],
    ["http://h/a b", { "hostname" => "h", "path" => "/a b", "raw_path" => "/a b", "scheme" => "http" }, true],
    ["ht tp://h", nil, false],
    ["h ttp", { "path" => "h ttp", "raw_path" => "h ttp" }, true]
  ].each do |uri, expected, expected_valid|
    it "parses and validates #{uri.inspect}" do
      expect(parse(uri)).to eq(expected.nil? ? :undef : expected)
      expect(valid?(uri)).to be(expected_valid)
    end
  end

  it "percent-decodes a path to raw bytes (matching Go's byte-oriented url.Path)" do
    # A %XX sequence that decodes to invalid UTF-8 yields the raw byte (like the gem's
    # urlquery.decode and OPA's internal value); OPA's JSON output renders it as U+FFFD.
    expect(parse("http://h/%FF")["path"].bytes).to eq([0x2f, 0xff])
    expect(parse("http://h/%FF%FE")["path"].bytes).to eq([0x2f, 0xff, 0xfe])
    # valid UTF-8 percent-encoding decodes normally
    expect(parse("http://h/caf%C3%A9")["path"]).to eq("/café")
  end

  it "parses a BINARY (ASCII-8BIT) string as raw bytes, matching OPA's byte-oriented net/url" do
    # base64.decode yields an ASCII-8BIT string, so `uri.parse(base64.decode(...))` is a real Rego
    # path; net/url parses raw bytes, so the gem must too (verified byte-exact against opa eval).
    euro = parse("\xE2\x82\xAC/".b) # base64.decode("4oKsLw==")
    expect(euro["path"].bytes).to eq([0xE2, 0x82, 0xAC, 0x2f])
    expect(euro["raw_path"].bytes).to eq([0xE2, 0x82, 0xAC, 0x2f])
    expect(parse("http://\xC3\xA9/".b)["hostname"].bytes).to eq([0xC3, 0xA9])
    expect(parse("\xFF".b)["path"].bytes).to eq([0xFF]) # OPA renders U+FFFD in JSON; value is the byte
    expect(valid?("\xE2\x82\xAC/".b)).to be(true)
    # An invalid-UTF-8 byte in the hostname position must carry through, not raise (the unescape
    # output flows into split_host_port, whose rindex/slice ops are byte-safe). Matches opa.
    expect(parse("http://\xFF/".b)["hostname"].bytes).to eq([0xFF])
    expect(parse("http://\xFF:80/".b).values_at("hostname", "port").map(&:bytes)).to eq([[0xFF], [0x38, 0x30]])
    expect(valid?("http://\xFF:80/".b)).to be(true)
  end

  it "treats an invalid-encoding or ASCII-incompatible string as unparseable instead of raising" do
    # A UTF-8-tagged string with invalid bytes (count/split/downcase raise) or an ASCII-incompatible
    # one (UTF-16 breaks rindex(":")) would abort the whole evaluation; the entry guard rejects them.
    # Neither is reachable through Rego (base64.decode is ASCII-8BIT; input/literals are valid UTF-8).
    [
      "ab\xFF?".dup.force_encoding("UTF-8"),
      "http://h/p".encode("UTF-16LE")
    ].each do |bad|
      expect { parse(bad) }.not_to raise_error
      expect(parse(bad)).to eq(:undef)
      expect { valid?(bad) }.not_to raise_error
      expect(valid?(bad)).to be(false)
    end
  end

  it "is_valid is false for a non-string argument (matching OPA's StringOperand error path)" do
    expect(registry.call("uri.is_valid", [Ruby::Rego::NumberValue.new(42)]).to_ruby).to be(false)
  end

  it "uri.parse is undefined for a non-string argument" do
    expect(registry.call("uri.parse", [Ruby::Rego::NumberValue.new(42)])).to be_a(Ruby::Rego::UndefinedValue)
  end
end
# rubocop:enable Metrics/BlockLength
