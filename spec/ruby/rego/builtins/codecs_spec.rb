# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe "encoding builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  describe "json.marshal" do
    it "sorts object keys and emits compact JSON (matching OPA)" do
      value = { "b" => 1, "a" => [2, 3], "c" => true }
      expect(registry.call("json.marshal", [value]).to_ruby).to eq('{"a":[2,3],"b":1,"c":true}')
    end

    it "marshals scalars and arrays" do
      expect(registry.call("json.marshal", [[1, "x", nil]]).to_ruby).to eq('[1,"x",null]')
    end

    it "marshals a set as a sorted array (matching OPA)" do
      expect(registry.call("json.marshal", [Set.new([3, 1, 2])]).to_ruby).to eq("[1,2,3]")
      expect(registry.call("json.marshal", [{ "s" => Set.new([3, 1, 2]) }]).to_ruby).to eq('{"s":[1,2,3]}')
    end

    it "orders composite set elements element-wise, not by serialized string (matching OPA)" do
      expect(registry.call("json.marshal", [Set.new([[2], [10]])]).to_ruby).to eq("[[2],[10]]")
      expect(registry.call("json.marshal", [Set.new(%w[a b aa])]).to_ruby).to eq('["a","aa","b"]')
    end

    it "orders a set of objects lexicographically by sorted pairs, not by key count (matching OPA)" do
      set = Set.new([{ "a" => 1, "b" => 1 }, { "z" => 1 }])
      expect(registry.call("json.marshal", [set]).to_ruby).to eq('[{"a":1,"b":1},{"z":1}]')
    end

    it "ranks a nested set above an object in term order (not flattened to an array), matching OPA" do
      set = Set.new([{ "a" => 2 }, Set.new([2, 3])])
      expect(registry.call("json.marshal", [set]).to_ruby).to eq('[{"a":2},[2,3]]')
    end

    it "orders a set of objects by raw-term key order, not stringified keys (matching OPA)" do
      expect(registry.call("json.marshal", [Set.new([{ 2 => "x" }, { 10 => "x" }])]).to_ruby)
        .to eq('[{"2":"x"},{"10":"x"}]')
      expect(registry.call("json.marshal", [Set.new([{ true => "b" }, { 2 => "a" }])]).to_ruby)
        .to eq('[{"true":"b"},{"2":"a"}]')
    end

    it "HTML-escapes <, > and & like Go's encoding/json (matching OPA)" do
      result = registry.call("json.marshal", ["<a>&b"]).to_ruby
      expected = format('"\u%<lt>04xa\u%<gt>04x\u%<amp>04xb"', lt: "<".ord, gt: ">".ord, amp: "&".ord)
      expect(result).to eq(expected)
      expect(result).not_to include("<", ">", "&")
    end

    it "escapes the U+2028/U+2029 separators (matching OPA)" do
      result = registry.call("json.marshal", ["\u2028\u2029"]).to_ruby
      expect(result).to eq(format('"\u%<ls>04x\u%<ps>04x"', ls: 0x2028, ps: 0x2029))
    end

    it "is undefined for a non-finite number rather than raising" do
      expect(registry.call("json.marshal", [Ruby::Rego::NumberValue.new(Float::INFINITY)]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for an over-deeply-nested value rather than raising" do
      deep = (1..200).reduce(1) { |acc, _| [acc] }
      expect(registry.call("json.marshal", [deep])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a set containing NaN rather than raising on the sort" do
      expect(registry.call("json.marshal", [Set.new([Float::NAN, 1.0])]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "json.unmarshal" do
    it "parses JSON into a value" do
      expect(registry.call("json.unmarshal", ['{"x":[1,2]}']).to_ruby).to eq("x" => [1, 2])
    end

    it "is undefined for invalid JSON" do
      expect(registry.call("json.unmarshal", ["{bad}"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "json.is_valid" do
    it "reports validity" do
      expect(registry.call("json.is_valid", ['{"x":1}']).to_ruby).to be(true)
      expect(registry.call("json.is_valid", ["{bad}"]).to_ruby).to be(false)
    end
  end

  describe "base64.encode / base64.decode" do
    it "round-trips standard base64 with padding" do
      expect(registry.call("base64.encode", ["hello"]).to_ruby).to eq("aGVsbG8=")
      expect(registry.call("base64.decode", ["aGVsbG8="]).to_ruby).to eq("hello")
    end

    it "is undefined when decoding unpadded standard base64 (matching OPA)" do
      expect(registry.call("base64.decode", ["aGVsbG8"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "base64.is_valid" do
    it "reports validity for standard base64" do
      expect(registry.call("base64.is_valid", ["aGVsbG8="]).to_ruby).to be(true)
      expect(registry.call("base64.is_valid", ["not!base64"]).to_ruby).to be(false)
    end

    it "treats unpadded input as invalid (matching OPA strict decode)" do
      expect(registry.call("base64.is_valid", ["aGVsbG8"]).to_ruby).to be(false)
    end
  end

  describe "base64url.encode / base64url.decode" do
    it "uses the URL-safe alphabet with padding" do
      expect(registry.call("base64url.encode", ["hi>?>"]).to_ruby).to eq("aGk-Pz4=")
      expect(registry.call("base64url.decode", ["aGk-Pz4="]).to_ruby).to eq("hi>?>")
    end

    it "decodes unpadded URL-safe input (matching OPA's lenient decode)" do
      expect(registry.call("base64url.decode", ["aGk-Pz4"]).to_ruby).to eq("hi>?>")
    end
  end

  describe "hex.encode / hex.decode" do
    it "round-trips lowercase hex" do
      expect(registry.call("hex.encode", ["hi"]).to_ruby).to eq("6869")
      expect(registry.call("hex.decode", ["6869"]).to_ruby).to eq("hi")
    end

    it "is undefined for non-hex or odd-length input" do
      expect(registry.call("hex.decode", ["zz"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("hex.decode", ["686"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "urlquery.encode / urlquery.decode" do
    it "percent-encodes like Go's url.QueryEscape (space to +)" do
      expect(registry.call("urlquery.encode", ["a b&c=d"]).to_ruby).to eq("a+b%26c%3Dd")
    end

    it "decodes query encoding" do
      expect(registry.call("urlquery.decode", ["a+b%26c"]).to_ruby).to eq("a b&c")
    end

    it "is undefined for a malformed percent-escape (matching OPA)" do
      expect(registry.call("urlquery.decode", ["%ZZ"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("urlquery.decode", ["%2"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  it "is undefined for non-string arguments" do
    expect(registry.call("base64.encode", [123])).to be_a(Ruby::Rego::UndefinedValue)
    expect(registry.call("hex.encode", [[]])).to be_a(Ruby::Rego::UndefinedValue)
  end

  # Values below verified against `opa eval` 1.17.
  describe "base64url.encode_no_pad" do
    it "encodes without padding (matching OPA)" do
      expect(registry.call("base64url.encode_no_pad", ["hello world"]).to_ruby).to eq("aGVsbG8gd29ybGQ")
      expect(registry.call("base64url.encode_no_pad", ["foobar"]).to_ruby).to eq("Zm9vYmFy")
      expect(registry.call("base64url.encode_no_pad", [""]).to_ruby).to eq("")
    end

    it "is undefined for a non-string argument" do
      expect(registry.call("base64url.encode_no_pad", [7])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "urlquery.encode_object" do
    it "sorts keys, expands arrays, and escapes keys and values" do
      expect(registry.call("urlquery.encode_object", [{ "b" => "2", "a" => "1", "c" => "3" }]).to_ruby)
        .to eq("a=1&b=2&c=3")
      expect(registry.call("urlquery.encode_object", [{ "k" => %w[v1 v2] }]).to_ruby).to eq("k=v1&k=v2")
      expect(registry.call("urlquery.encode_object", [{ "key with space" => "a&b=c", "x" => "y/z" }]).to_ruby)
        .to eq("key+with+space=a%26b%3Dc&x=y%2Fz")
      expect(registry.call("urlquery.encode_object", [{ "b" => "2", "a" => %w[x y], "c" => "" }]).to_ruby)
        .to eq("a=x&a=y&b=2&c=")
    end

    it "sorts and de-duplicates a set value (matching OPA)" do
      expect(registry.call("urlquery.encode_object", [{ "k" => Set["z", "a", "m"] }]).to_ruby).to eq("k=a&k=m&k=z")
    end

    it "emits nothing for an empty object or empty array value" do
      expect(registry.call("urlquery.encode_object", [{}]).to_ruby).to eq("")
      expect(registry.call("urlquery.encode_object", [{ "k" => [] }]).to_ruby).to eq("")
    end

    it "leaves an unreserved tilde unescaped (matching OPA; stable since Ruby 3.3)" do
      expect(registry.call("urlquery.encode_object", [{ "k" => "a~b" }]).to_ruby).to eq("k=a~b")
    end

    # A non-ASCII-compatible string (UTF-16, reachable only via the Ruby API) makes
    # CGI.escape raise; it must yield undefined, not escape as a hard error. Covers a
    # single key, a non-ASCII-content value, and the multi-key sort path (String#<=> always
    # byte-compares two strings, so the sort itself never raises — CGI.escape is the only
    # raise site, caught by the EncodingError rescue).
    it "is undefined for a non-ASCII-compatible key or value (Ruby API only)" do
      expect(registry.call("urlquery.encode_object", [{ "k" => "x".encode("UTF-16LE") }]))
        .to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("urlquery.encode_object", [{ "é".encode("UTF-16LE") => "1", "ü" => "2" }]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a non-object or a non-string/array-of-strings value" do
      expect(registry.call("urlquery.encode_object", [7])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("urlquery.encode_object", [{ "k" => 5 }])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("urlquery.encode_object", [{ "k" => [true] }])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("urlquery.encode_object", [{ "k" => ["a", 1] }])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("urlquery.encode_object", [{ "k" => { "x" => "y" } }])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("urlquery.encode_object", [{ "k" => nil }])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "urlquery.decode_object" do
    it "decodes a query string to an object of value arrays" do
      expect(registry.call("urlquery.decode_object", ["a=1&b=2"]).to_ruby).to eq("a" => ["1"], "b" => ["2"])
      expect(registry.call("urlquery.decode_object", ["k=v1&k=v2&j=x"]).to_ruby)
        .to eq("k" => %w[v1 v2], "j" => ["x"])
      expect(registry.call("urlquery.decode_object", [""]).to_ruby).to eq({})
    end

    it "treats a key with no value as empty, and unescapes + and percent escapes" do
      expect(registry.call("urlquery.decode_object", ["a&b=2"]).to_ruby).to eq("a" => [""], "b" => ["2"])
      expect(registry.call("urlquery.decode_object", ["a=hello%20world&b=x+y"]).to_ruby)
        .to eq("a" => ["hello world"], "b" => ["x y"])
    end

    it "is undefined for a malformed percent-escape in key or value (matching OPA)" do
      expect(registry.call("urlquery.decode_object", ["a=%2"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("urlquery.decode_object", ["%2=b"])).to be_a(Ruby::Rego::UndefinedValue)
    end

    # Go's url.ParseQuery (since 1.17) rejects a literal ";"; an escaped %3B is fine.
    it "is undefined for a literal semicolon but accepts an escaped one (matching OPA)" do
      expect(registry.call("urlquery.decode_object", ["a=1;b=2"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("urlquery.decode_object", ["a=b%3Bc"]).to_ruby).to eq("a" => ["b;c"])
    end

    it "is undefined for a non-string argument" do
      expect(registry.call("urlquery.decode_object", [123])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a non-ASCII-compatible string (Ruby API only)" do
      expect(registry.call("urlquery.decode_object", ["a=1".encode("UTF-16LE")]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end

# rubocop:enable Metrics/BlockLength
