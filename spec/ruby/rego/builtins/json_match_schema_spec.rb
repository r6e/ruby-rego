# frozen_string_literal: true

require "json"

# json.match_schema(document, schema) -> [match, errors]. OPA wraps Go's xeipuuv/gojsonschema, a
# non-standard permissive multi-draft superset. Only the BOOLEAN `match` is a byte-exact contract; the
# errors array is best-effort (gojsonschema's {desc,error,field,type} objects are a documented divergence),
# so these assert the boolean exactly and the array's PRESENCE (empty vs non-empty), not its content/count.
# An unusable schema or document argument yields undefined, matching OPA. Goldens captured from `opa eval`
# 1.17. The `format` keyword enforces the lexical / date-time / net / regex / uri-family and email/idn-email
# assertions (see the "format assertions" describe block).
# rubocop:disable Metrics/BlockLength
RSpec.describe "json.match_schema" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  fixtures = File.expand_path("../../../fixtures/json_schema", __dir__)
  goldens = JSON.parse(File.read(File.join(fixtures, "match_schema_goldens.json")))
  format_goldens = JSON.parse(File.read(File.join(fixtures, "match_schema_format_goldens.json")))

  # Forwards the document and schema as a policy would: registry.call converts each Ruby value to its Value
  # (a String -> StringValue for the string-loader path, a Hash -> ObjectValue, a number/bool/nil/array ->
  # the matching Value), and the builtin then dispatches — so a string/object schema may be usable while a
  # number/bool/null/array schema is undefined. Returns the raw Value so an undefined result is
  # distinguishable from a [match, errors] pair.
  def call_match(document, schema)
    registry.call("json.match_schema", [document, schema])
  end

  describe "matches OPA (boolean byte-exact, error presence)" do
    goldens.each do |name, fixture|
      it "agrees with OPA on #{name}" do
        result = call_match(fixture.fetch("doc"), fixture.fetch("schema"))
        expected = fixture.fetch("expected")

        if expected == "__undef__"
          expect(result).to be_a(Ruby::Rego::UndefinedValue)
          next
        end

        match, errors = result.to_ruby
        expect(match).to eq(expected)
        # errors is empty exactly when the document matches.
        expect(errors.empty?).to eq(expected)
      end
    end
  end

  # The `format` keyword (gojsonschema's enforced format assertions; format_checkers.go). Only the boolean is
  # contractual. The lexical / date-time / net / regex / uri-family and email/idn-email formats are enforced;
  # the genuinely unenforced names (idn-hostname, duration, unknown) stay annotation-only (true). Goldens
  # captured from opa eval 1.17.
  describe "format assertions (matches OPA)" do
    format_goldens.each do |name, fixture|
      it "agrees with OPA on #{name}" do
        match, = call_match(fixture.fetch("doc"), fixture.fetch("schema")).to_ruby
        expect(match).to eq(fixture.fetch("expected"))
      end
    end

    # Go's ^..$ match whole text (RE2 default), so a leading/trailing/embedded newline is rejected — unlike
    # Ruby's line-oriented ^..$. The format regexes are anchored \A..\z to reproduce this.
    it "rejects newlines (Go anchors are whole-text, not per-line)" do
      %w[hostname uuid date time ipv4 ipv6].each do |fmt|
        base = { "hostname" => "example.com", "uuid" => "12345678-1234-1234-1234-123456789012",
                 "date" => "2018-11-13", "time" => "20:20:39", "ipv4" => "1.2.3.4", "ipv6" => "::1" }[fmt]
        schema = { "type" => "string", "format" => fmt }
        expect(call_match(JSON.generate(base), schema).to_ruby[0]).to be(true)
        expect(call_match(JSON.generate("#{base}\n"), schema).to_ruby[0]).to be(false)
      end
    end

    # date-time tries five Go layouts, so it also accepts a bare date or bare time, and requires an uppercase
    # T plus a zone for the full form.
    it "accepts bare date or bare time for date-time, but requires T and a zone for the full form" do
      dt = { "type" => "string", "format" => "date-time" }
      expect(call_match(JSON.generate("2018-11-13"), dt).to_ruby[0]).to be(true)
      expect(call_match(JSON.generate("20:20:39"), dt).to_ruby[0]).to be(true)
      expect(call_match(JSON.generate("2018-11-13T20:20:39Z"), dt).to_ruby[0]).to be(true)
      expect(call_match(JSON.generate("2018-11-13T20:20:39"), dt).to_ruby[0]).to be(false)
      expect(call_match(JSON.generate("2018-11-13t20:20:39z"), dt).to_ruby[0]).to be(false)
    end

    # gojsonschema does not register idn-hostname or duration, and ignores unknown formats — all
    # annotation-only, so any string matches.
    it "treats unenforced/unknown formats as annotation-only (always matches)" do
      %w[duration idn-hostname totally-made-up].each do |fmt|
        schema = { "type" => "string", "format" => fmt }
        expect(call_match(JSON.generate("anything at all"), schema).to_ruby[0]).to be(true)
        expect(call_match(JSON.generate(""), schema).to_ruby[0]).to be(true)
      end
    end

    # uri/iri require a parseable Go net/url with a non-empty scheme + no backslash; uri-reference/iri-reference
    # drop the scheme requirement; uri-template adds gojsonschema's path-template regex. iri == uri (url.Parse
    # already accepts unicode). Reuses the gem's Uri::Parser (net/url port), differentially verified vs OPA.
    it "enforces the uri family via Go net/url semantics" do
      uri = ->(v, fmt) { call_match(JSON.generate(v), { "type" => "string", "format" => fmt }).to_ruby[0] }
      # uri / iri: scheme required, identical
      %w[uri iri].each do |fmt|
        expect(uri.call("http://example.com", fmt)).to be(true)
        expect(uri.call("//example.com", fmt)).to be(false) # no scheme
        expect(uri.call("foo", fmt)).to be(false)
        expect(uri.call("urn:isbn:0451450523", fmt)).to be(true)
        expect(uri.call("http://例子.广告", fmt)).to be(true) # unicode host (iri==uri)
        expect(uri.call("foo\\bar", fmt)).to be(false)       # backslash
        expect(uri.call("http://a b", fmt)).to be(false)     # space in authority fails url.Parse
      end
      # uri-reference / iri-reference: scheme optional
      %w[uri-reference iri-reference].each do |fmt|
        expect(uri.call("/path", fmt)).to be(true)
        expect(uri.call("foo", fmt)).to be(true)
        expect(uri.call("a\\b", fmt)).to be(false) # backslash still rejected
      end
      # uri-template: path-template regex
      expect(uri.call("http://example.com/{id}", "uri-template")).to be(true)
      expect(uri.call("http://example.com/{id", "uri-template")).to be(false)  # unclosed brace
      expect(uri.call("http://example.com/}{", "uri-template")).to be(false)   # close before open
    end

    # email / idn-email both run Go's net/mail.ParseAddress (a full RFC 5322 address parse, not a "valid
    # email" check), so the boundary is idiosyncratic: a display name + angle-addr parses, a single-member
    # group parses but a multi-member one does not, a leading comment fails while a trailing one passes, a
    # domain-literal must be a net.ParseIP address, and RFC 6532 UTF-8 is allowed in atoms. idn-email is the
    # SAME checker. Differentially verified vs OPA; see MailAddress.
    it "enforces email/idn-email via Go net/mail.ParseAddress semantics" do
      email = ->(v, fmt) { call_match(JSON.generate(v), { "type" => "string", "format" => fmt }).to_ruby[0] }
      %w[email idn-email].each do |fmt|
        expect(email.call("foo@bar.com", fmt)).to be(true)
        expect(email.call("a@b", fmt)).to be(true)
        expect(email.call("实例@例子", fmt)).to be(true) # RFC 6532 UTF-8 atoms
        expect(email.call("a", fmt)).to be(false)               # no @
        expect(email.call("g: a@b;", fmt)).to be(true)          # single-member group parses
        expect(email.call("(comment) a@b", fmt)).to be(false)   # leading comment fails
      end
      # email-only spread of the parser's quirks (idn-email is identical, exercised above)
      expect(email.call("Foo <a@b>", "email")).to be(true)      # display name + angle-addr
      expect(email.call("a@b (comment)", "email")).to be(true)  # trailing comment ok
      expect(email.call("a (c) @b", "email")).to be(false)      # comment at the local/@ boundary fails
      expect(email.call("a@b, c@d", "email")).to be(false)      # parseSingleAddress: one address only
      expect(email.call("a@[127.0.0.1]", "email")).to be(true)  # domain-literal = net.ParseIP
      expect(email.call("a@[IPv6:::1]", "email")).to be(false)  # Go's net.ParseIP rejects the tag
      expect(email.call("\"\"@c", "email")).to be(false)        # empty quoted local-part
      expect(email.call("a..b@b", "email")).to be(false)        # double dot in dot-atom
    end

    # Go 1.26's consumePhrase (OPA 1.17.1's build) runs mime.WordDecoder.Decode on each display-name atom
    # (RFC 2047 encoded-words). A structurally valid =?charset?enc?text?= whose payload decodes but whose
    # charset is not utf-8/iso-8859-1/us-ascii makes Decode error (rejecting as the first word, truncating
    # otherwise); an empty payload decodes to "" (dropped); a malformed/undecodable word is kept as raw text.
    # Go 1.26 also buffers a RUN of consecutive encoded-words and only flushes to its `words` slice on a
    # following raw word, so the comment-consuming CFWS skip (gated on len(words)>0) does NOT run after a lone
    # encoded-word run — a comment there ends the phrase. Characterized exhaustively vs opa (19000+ cases).
    it "applies Go 1.26's RFC 2047 decodeRFC2047Word + encoded-word CFWS gating in display-name phrases" do
      email = ->(v) { call_match(JSON.generate(v), { "type" => "string", "format" => "email" }).to_ruby[0] }
      expect(email.call("=?utf-8?q?foo?= <a@b>")).to be(true) # supported charset decodes
      expect(email.call("=?UTF-8?B?Zm9v?= <a@b>")).to be(true) # base64, case-insensitive charset
      expect(email.call("=?unknown?q?y?= <a@b>")).to be(false)           # unsupported charset, first word
      expect(email.call("Foo =?unknown?q?y?= <a@b>")).to be(true)        # unsupported later -> phrase truncates
      expect(email.call("Foo =?unknown?q?y?= bar <a@b>")).to be(false)   # ...leftover "bar" is not an angle-addr
      expect(email.call("=?unknown?b?z?= <a@b>")).to be(true)            # bad base64 -> kept raw, not an error
      expect(email.call("=?utf-8?z?y?= <a@b>")).to be(true)             # bad encoding letter -> kept raw
      expect(email.call("=?utf-8?b??= <a@b>")).to be(false)             # empty payload -> dropped, no word left
      expect(email.call("=?utf-8?b??= =?utf-8?B?Zm9v?= <a@b>")).to be(true) # empty dropped, later word remains
      expect(email.call("=?utf-8?b??=@b")).to be(true) # only a phrase word, fine as local-part
      # Go 1.26 encoded-word-run CFWS gating: comment after a lone encoded run ends the phrase...
      expect(email.call("=?utf-8?B?Zm9v?= (c) <a@b>")).to be(false)
      expect(email.call("=?utf-8?B?Zm9v?= =?utf-8?B?YmFy?= (c) <a@b>")).to be(false)
      # ...but a raw word first flushes the run, so the comment is then consumed
      expect(email.call("Foo =?utf-8?B?Zm9v?= (c) <a@b>")).to be(true)
      expect(email.call("foo (c) <a@b>")).to be(true)
    end

    it "ignores format on a non-string instance (vacuously matches)" do
      expect(call_match("5", { "format" => "ipv4" }).to_ruby[0]).to be(true)
      expect(call_match({ "a" => 1 }, { "format" => "hostname" }).to_ruby[0]).to be(true)
    end

    it "uses proleptic Gregorian for date (not Ruby's Julian-before-1582 default)" do
      # 1500 is a leap year in Julian but NOT in proleptic Gregorian, so Feb 29 1500 is invalid (like Go).
      expect(call_match(JSON.generate("1500-02-29"),
                        { "type" => "string", "format" => "date" }).to_ruby[0]).to be(false)
    end

    it "does not raise on a binary / invalid-UTF-8 format value" do
      bad = (+"\xFF\xFE").force_encoding("UTF-8")
      # the uri family routes through Uri::Parser and email through MailAddress, both of which raise on
      # invalid-UTF-8 — the scannable? guard + rescue must keep every format total
      %w[hostname uuid date regex ipv4 uri uri-reference iri iri-reference uri-template email idn-email]
        .each do |fmt|
        expect { call_match({ "v" => bad }, { "properties" => { "v" => { "format" => fmt } } }) }.not_to raise_error
      end
    end

    # format: "regex" reuses the RE2 compile gate, bounded against the gem's RE2 being far slower than Go's:
    # RE2_MAX_MEM caps the compile phase (nested counted repetition is ~quadratic) and RE2_MAX_PATTERN_BYTES
    # caps the parse phase (unicode-class expansion is linear in length, which max_mem doesn't bound). Both
    # fast-fail an over-budget pattern to invalid. The cost is a documented divergence: such a pattern
    # (pathological repetition, a large unicode bounded-repeat, or any pattern over the byte cap) is rejected
    # where OPA accepts it. Security over byte-exactness here.
    it "caps regex compilation, rejecting over-budget patterns OPA accepts (no compile/parse DoS)" do
      regex = { "type" => "string", "format" => "regex" }
      expect(call_match(JSON.generate("^[a-z]+$"), regex).to_ruby[0]).to be(true)
      expect(call_match(JSON.generate("x#{"a{500,1000}" * 300}"), regex).to_ruby[0]).to be(false) # compile DoS
      expect(call_match(JSON.generate("\\p{L}{1,64}"), regex).to_ruby[0]).to be(false) # divergence: OPA true
      expect(call_match(JSON.generate("(\\p{L}{1,400})" * 70_000), regex).to_ruby[0]).to be(false) # ~1MB parse DoS
    end
  end

  # patternProperties tests every schema pattern against every document property name, so the Matcher
  # memoizes each distinct compiled regex per call (N compiles, not N×M) — a DoS guard. These pin that the
  # cache keys on the pattern (distinct patterns enforce their own subschema, never conflated).
  describe "patternProperties (per-call regex memoization)" do
    it "enforces each distinct pattern's subschema independently" do
      # unanchored patterns: "a" matches any name containing a, "b" any name containing b
      schema = { "patternProperties" => { "a" => { "type" => "integer" }, "b" => { "type" => "string" } } }
      expect(call_match({ "xa" => 5, "xb" => "s" }, schema).to_ruby[0]).to be(true)
      expect(call_match({ "xa" => "s" }, schema).to_ruby[0]).to be(false) # "a" wants integer
      expect(call_match({ "xb" => 5 }, schema).to_ruby[0]).to be(false)   # "b" wants string
      # a name matching BOTH patterns must satisfy both subschemas (no cache cross-talk); 5 fails "b"'s string
      expect(call_match({ "ab" => 5 }, schema).to_ruby[0]).to be(false)
    end

    it "stays fast on many distinct patterns against many properties (no N×M recompile)" do
      patterns = (0...60).to_h { |i| ["^x#{i}", { "type" => "string" }] }
      document = (0...60).to_h { |j| ["x#{j}field", "value"] }
      expect { @r = call_match(document, { "patternProperties" => patterns }) }.not_to raise_error
      expect(@r.to_ruby[0]).to be(true)
    end
  end

  describe "result shape" do
    it "returns [true, []] when the document matches" do
      expect(call_match("5", { "type" => "integer" }).to_ruby).to eq([true, []])
    end

    it "returns [false, <non-empty>] when the document does not match" do
      match, errors = call_match('"x"', { "type" => "integer" }).to_ruby
      expect(match).to be(false)
      expect(errors).not_to be_empty
    end
  end

  describe "document argument dispatch" do
    it "accepts a raw object or array document" do
      expect(call_match({ "a" => 1 }, { "type" => "object" }).to_ruby).to eq([true, []])
      expect(call_match([1, 2], { "type" => "array" }).to_ruby).to eq([true, []])
    end

    it "parses a JSON-string document to any value (object, array, or scalar)" do
      expect(call_match('{"a":1}', { "required" => ["a"] }).to_ruby[0]).to be(true)
      expect(call_match("42", { "type" => "integer" }).to_ruby[0]).to be(true)
      expect(call_match("true", { "type" => "boolean" }).to_ruby[0]).to be(true)
      expect(call_match("null", { "type" => "null" }).to_ruby[0]).to be(true)
    end

    it "is undefined for a raw scalar document (number/boolean/null), like gojsonschema's loader" do
      [42, true, nil].each do |document|
        expect(call_match(document, { "type" => "integer" })).to be_a(Ruby::Rego::UndefinedValue)
      end
    end

    it "is undefined for a JSON-string document that is not well-formed JSON" do
      expect(call_match("garbage", { "type" => "string" })).to be_a(Ruby::Rego::UndefinedValue)
    end

    # Ruby's JSON.parse accepts // and /* */ comments Go's encoding/json rejects, so a structural comment
    # in the document string makes it unusable (undefined), matching OPA.
    it "is undefined for // or /* */ comments in a JSON-string document" do
      ["{} //c", "/* c */ 5"].each do |document|
        expect(call_match(document, { "type" => "object" })).to be_a(Ruby::Rego::UndefinedValue)
      end
    end

    it "does not raise on a non-ascii-compatible / invalid-UTF-8 JSON-string document" do
      expect { @r = call_match('{"a":1}'.encode("UTF-16LE"), { "type" => "object" }) }.not_to raise_error
      expect(@r).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "schema argument dispatch" do
    it "is undefined for an invalid schema" do
      expect(call_match("5", { "type" => "bogus" })).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a non-string/non-object schema argument" do
      [42, true, nil, []].each do |schema|
        expect(call_match("5", schema)).to be_a(Ruby::Rego::UndefinedValue)
      end
    end

    it "parses a JSON-string schema" do
      expect(call_match("5", '{"type":"integer"}').to_ruby).to eq([true, []])
    end

    # A bare boolean schema (true/false) is undefined as a top-level OPA schema argument (raw scalar).
    it "is undefined for a bare boolean schema argument" do
      expect(call_match("5", true)).to be_a(Ruby::Rego::UndefinedValue)
      expect(call_match("5", false)).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "validation semantics (spot checks against gojsonschema behavior)" do
    it "treats an integral float as an integer" do
      expect(call_match("5.0", { "type" => "integer" }).to_ruby[0]).to be(true)
      expect(call_match("5.5", { "type" => "integer" }).to_ruby[0]).to be(false)
    end

    it "matches pattern unanchored with RE2" do
      expect(call_match('"xabcy"', { "pattern" => "abc" }).to_ruby[0]).to be(true)
    end

    it "compares enum/const/uniqueItems by JSON value (1 == 1.0)" do
      expect(call_match("1.0", { "enum" => [1] }).to_ruby[0]).to be(true)
      expect(call_match("1", { "const" => 1.0 }).to_ruby[0]).to be(true)
      expect(call_match("[1, 1.0]", { "uniqueItems" => true }).to_ruby[0]).to be(false)
    end

    # gojsonschema feeds numbers through Go's encoding/json (float64), so integers past 2^53 collapse in
    # equality comparisons (enum/const/uniqueItems) — and so must the gem, via canonical's `to_f`. Switching
    # to exact Rational here would DIVERGE from OPA. (multipleOf is a separate big.Rat path and stays exact.)
    # Verified against opa eval 1.17: const 2^53 matches a 2^53+1 document; [2^53, 2^53+1] is non-unique.
    it "collapses integers past 2^53 in equality, matching gojsonschema's float64 (not exact Rational)" do
      expect(call_match("9007199254740993", { "const" => 9_007_199_254_740_992 }).to_ruby[0]).to be(true)
      expect(call_match("9007199254740993", { "enum" => [9_007_199_254_740_992] }).to_ruby[0]).to be(true)
      expect(call_match("[9007199254740992, 9007199254740993]", { "uniqueItems" => true }).to_ruby[0]).to be(false)
      # +2 rounds to a distinct float, so it stays unique — matching OPA
      expect(call_match("[9007199254740992, 9007199254740994]", { "uniqueItems" => true }).to_ruby[0]).to be(true)
    end

    it "respects boolean and numeric exclusiveMinimum (draft-04 and draft-06 forms)" do
      expect(call_match("5", { "minimum" => 5, "exclusiveMinimum" => true }).to_ruby[0]).to be(false)
      expect(call_match("5", { "exclusiveMinimum" => 5 }).to_ruby[0]).to be(false)
      expect(call_match("6", { "exclusiveMinimum" => 5 }).to_ruby[0]).to be(true)
    end

    # gojsonschema treats empty enum / type / anyOf / oneOf arrays as no constraint (matches anything),
    # unlike the JSON-Schema standard where an empty enum/anyOf/oneOf admits nothing. (allOf:[] is true in
    # both.) Confirmed against opa eval 1.17.
    it "treats empty enum / type / anyOf / oneOf arrays as no constraint (matches anything)" do
      expect(call_match("1", { "enum" => [] }).to_ruby[0]).to be(true)
      expect(call_match("5", { "type" => [] }).to_ruby[0]).to be(true)
      expect(call_match("5", { "anyOf" => [] }).to_ruby[0]).to be(true)
      expect(call_match("5", { "oneOf" => [] }).to_ruby[0]).to be(true)
      # the empty anyOf is vacuously satisfied, so `not` of it fails
      expect(call_match("5", { "not" => { "anyOf" => [] } }).to_ruby[0]).to be(false)
    end

    # gojsonschema only wires additionalItems inside a NON-empty `items` tuple, so an empty `items` array
    # leaves every element unconstrained (additionalItems ignored) — opposite of the JSON-Schema standard.
    it "ignores additionalItems when the items tuple is empty" do
      expect(call_match("[1,2,3]", { "items" => [], "additionalItems" => false }).to_ruby[0]).to be(true)
      expect(call_match("[1]", { "items" => [], "additionalItems" => { "type" => "string" } }).to_ruby[0]).to be(true)
      # a non-empty tuple still enforces additionalItems
      expect(call_match("[1,2]",
                        { "items" => [{ "type" => "integer" }], "additionalItems" => false }).to_ruby[0]).to be(false)
    end

    # multipleOf uses arbitrary-precision decimal arithmetic (gojsonschema's big.Rat): a huge document over
    # a tiny divisor must not overflow to Infinity (which would raise FloatDomainError and abort the policy).
    it "handles multipleOf at extreme magnitudes without overflow (matches OPA's true)" do
      expect(call_match("1e308", { "multipleOf" => 1e-300 }).to_ruby[0]).to be(true)
      expect(call_match("1e308", { "multipleOf" => 1 }).to_ruby[0]).to be(true)
      expect(call_match("100000000000000000000000000000000000000000", { "multipleOf" => 1 }).to_ruby[0]).to be(true)
      expect(call_match("6", { "multipleOf" => 1.5 }).to_ruby[0]).to be(true)
      expect(call_match("7", { "multipleOf" => 2 }).to_ruby[0]).to be(false)
    end
  end

  # OPA marshals the document to JSON before gojsonschema sees it, so a Rego object with non-string keys
  # (legal in Rego) validates as if its keys were stringified (1 -> "1", true -> "true"). The gem must match
  # this AND not raise (a mixed-key object would otherwise make canonical's sort compare 1 <=> "b" -> nil ->
  # ArgumentError, aborting the policy). Documents here are raw Ruby hashes (a JSON string can't carry them).
  describe "non-string object keys (Rego objects)" do
    it "stringifies keys for enum/const equality (int/bool key matches the string-keyed value)" do
      expect(call_match({ 1 => "a", "b" => 2 }, { "enum" => [{ 1 => "a", "b" => 2 }] }).to_ruby).to eq([true, []])
      expect(call_match({ 1 => "a" }, { "enum" => [{ "1" => "a" }] }).to_ruby[0]).to be(true)
      expect(call_match({ true => "a" }, { "const" => { "true" => "a" } }).to_ruby[0]).to be(true)
    end

    it "stringifies keys for required/properties/propertyNames" do
      expect(call_match({ 1 => "a", 2 => "b" }, { "required" => %w[1 2] }).to_ruby[0]).to be(true)
      expect(call_match({ 1 => 5 }, { "properties" => { "1" => { "type" => "integer" } } }).to_ruby[0]).to be(true)
      expect(call_match({ 1 => 5 }, { "properties" => { "1" => { "type" => "string" } } }).to_ruby[0]).to be(false)
    end

    it "does not raise on a mixed-key object compared via enum (canonical sort stays total)" do
      expect { @r = call_match({ 1 => "a", "b" => 2, true => 3 }, { "enum" => [{}] }) }.not_to raise_error
      expect(@r.to_ruby[0]).to be(false)
    end
  end

  describe "$ref and cycle safety" do
    it "validates the document against a resolved in-document $ref" do
      schema = { "definitions" => { "pos" => { "type" => "integer", "minimum" => 1 } },
                 "$ref" => "#/definitions/pos" }
      expect(call_match("5", schema).to_ruby[0]).to be(true)
      expect(call_match("0", schema).to_ruby[0]).to be(false)
    end

    it "terminates on a self-referential schema (recursive list)" do
      schema = { "definitions" => { "node" => { "type" => "object",
                                                "properties" => { "next" => { "$ref" => "#/definitions/node" } } } },
                 "$ref" => "#/definitions/node" }
      expect { @r = call_match('{"next":{"next":{}}}', schema) }.not_to raise_error
      expect(@r.to_ruby[0]).to be(true)
    end
  end

  describe "totality" do
    it "does not raise on an invalid-UTF-8 pattern in the schema" do
      bad = (+"\xFF").force_encoding("UTF-8")
      expect { @r = call_match('"x"', { "pattern" => bad }) }.not_to raise_error
    end

    # multipleOf:0 would make multiple_of? divide by zero (Infinity.round -> FloatDomainError); valid_schema
    # rejects a non-positive multipleOf first, so it is undefined — matching OPA, which also returns undefined.
    it "is undefined for multipleOf:0 (never reaches the divide)" do
      expect(call_match("5", { "multipleOf" => 0 })).to be_a(Ruby::Rego::UndefinedValue)
    end

    # A JSON literal like 1e400 overflows Float to Infinity; building a Rational from "Infinity"/"NaN" would
    # raise ArgumentError and abort the policy. multipleOf must stay total on non-finite numbers (returns
    # false — the gem's Float model can't represent these magnitudes, a documented number-model divergence).
    it "does not raise on a non-finite (Infinity/NaN) number under multipleOf" do
      expect do
        @r = call_match('{"a": 1e400}', { "properties" => { "a" => { "multipleOf" => 3 } } })
      end.not_to raise_error
      expect(@r.to_ruby[0]).to be(false)
      expect { call_match([1.0 / 0.0], { "items" => { "multipleOf" => 2 } }) }.not_to raise_error
      expect { call_match([0.0 / 0.0], { "items" => { "multipleOf" => 2 } }) }.not_to raise_error
      # a non-finite multipleOf in a raw-object schema must not raise either
      expect do
        call_match({ "a" => 6 }, { "properties" => { "a" => { "multipleOf" => 1.0 / 0.0 } } })
      end.not_to raise_error
    end

    # The validator recurses through matches?/canonical; without a bound a deep document or schema would
    # SystemStackError and abort the whole policy (only BuiltinArgumentError is rescued). Past MAX_DEPTH the
    # builtin returns undefined instead. gojsonschema validates deeper before it too stack-overflows, so this
    # is a documented divergence (undefined vs OPA's true), not a crash.
    it "returns undefined (never raises) for a document nested past the depth bound" do
      schema = { "definitions" => { "n" => { "type" => "object",
                                             "properties" => { "next" => { "$ref" => "#/definitions/n" } } } },
                 "$ref" => "#/definitions/n" }
      doc = {}
      node = doc
      300.times do
        node["next"] = {}
        node = node["next"]
      end
      expect { @r = call_match(doc, schema) }.not_to raise_error
      expect(@r).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "returns undefined (never raises) for a schema nested past the depth bound (deep allOf)" do
      schema = { "type" => "integer" }
      300.times { schema = { "allOf" => [schema] } }
      expect { @r = call_match("5", schema) }.not_to raise_error
      expect(@r).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "returns undefined (never raises) for a document/const compared past the depth bound" do
      deep = {}
      node = deep
      300.times do
        node["next"] = {}
        node = node["next"]
      end
      expect { @r = call_match(deep, { "const" => deep }) }.not_to raise_error
      expect(@r).to be_a(Ruby::Rego::UndefinedValue)
    end

    # A root self-reference ($ref:"#") stack-overflows gojsonschema (an OPA upstream crash); the gem's
    # [ref, document object id] visited-guard terminates it instead of bug-for-bug reproducing the panic.
    it "terminates on a root self-reference $ref:# that crashes OPA" do
      expect { @r = call_match({ "a" => 1 }, { "$ref" => "#" }) }.not_to raise_error
    end

    # A schema whose validity check recurses unboundedly (a long $ref chain) is rejected as invalid by the
    # shared verify engine, so match returns undefined rather than SystemStackError-ing the whole policy.
    # A chain a little past MAX_SCHEMA_DEPTH (100) trips the same recursion guard as a far longer one.
    it "is undefined (never raises) for a schema with a pathologically long $ref chain" do
      chain = 150
      defs = {}
      (0...chain).each { |i| defs["d#{i}"] = { "$ref" => "#/definitions/d#{i + 1}" } }
      defs["d#{chain}"] = { "type" => "integer" }
      schema = { "$ref" => "#/definitions/d0", "definitions" => defs }
      expect { @r = call_match("5", schema) }.not_to raise_error
      expect(@r).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "registration" do
    it "registers the builtin" do
      expect(registry.registered?("json.match_schema")).to be(true)
    end
  end
end
# rubocop:enable Metrics/BlockLength
