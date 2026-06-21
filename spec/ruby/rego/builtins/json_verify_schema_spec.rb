# frozen_string_literal: true

require "json"

# json.verify_schema(schema) -> [valid, error]. OPA wraps Go's xeipuuv/gojsonschema, a non-standard
# permissive multi-draft superset. Only the BOOLEAN `valid` is a byte-exact contract; the error STRING is
# best-effort (gojsonschema's exact Go wording is a documented divergence), so these assert the boolean
# exactly and the error's PRESENCE (null vs non-null), not its text. Goldens captured from `opa eval` 1.17.
# rubocop:disable Metrics/BlockLength
RSpec.describe "json.verify_schema" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  fixtures = File.expand_path("../../../fixtures/json_schema", __dir__)
  goldens = JSON.parse(File.read(File.join(fixtures, "verify_schema_goldens.json")))

  def verify(schema)
    # A raw String arg becomes a StringValue (the JSON-string path); a Hash/Array/scalar becomes the
    # matching Value — exactly the string-or-object dispatch OPA performs.
    registry.call("json.verify_schema", [schema]).to_ruby
  end

  describe "matches OPA (boolean byte-exact, error presence)" do
    goldens.each do |name, fixture|
      it "agrees with OPA on #{name}" do
        result = verify(fixture.fetch("schema"))
        expected = fixture.fetch("expected")
        expect(result[0]).to eq(expected[0])
        expect(result[1].nil?).to eq(expected[1].nil?)
      end
    end
  end

  describe "result shape" do
    it "returns [true, null] for a valid schema" do
      expect(verify({ "type" => "object" })).to eq([true, nil])
    end

    it "returns [false, <string>] for an invalid schema" do
      result = verify({ "type" => "bogus" })
      expect(result[0]).to be(false)
      expect(result[1]).to be_a(String)
    end
  end

  describe "argument dispatch" do
    it "parses a JSON-string schema" do
      expect(verify('{"type":"string"}')).to eq([true, nil])
    end

    it "treats a JSON boolean schema (via string) as valid" do
      expect(verify("true")).to eq([true, nil])
      expect(verify("false")).to eq([true, nil])
    end

    it "is invalid for a non-string/non-object argument (number/bool/null/array)" do
      [42, true, nil, []].each do |arg|
        expect(verify(arg)[0]).to be(false)
      end
    end

    it "is invalid for a string that is not JSON, or parses to a non-object scalar" do
      ["garbage", "", "42", '"x"'].each do |arg|
        expect(verify(arg)[0]).to be(false)
      end
    end

    # Ruby's JSON.parse accepts // and /* */ comments that Go's encoding/json (gojsonschema) rejects, so a
    # structural comment in a JSON-string schema is invalid; a comment-like sequence inside a string value
    # is legal JSON and stays valid (matching OPA).
    it "rejects // and /* */ comments in a JSON-string schema (like Go), but not inside string values" do
      ["{} //c", "/* c */ {}", '{"type":"string" /*x*/}'].each do |arg|
        expect(verify(arg)[0]).to be(false)
      end
      ['{"pattern":"a//b"}', '{"description":"see /* docs */"}'].each do |arg|
        expect(verify(arg)[0]).to be(true)
      end
    end

    it "does not raise on a non-ascii-compatible / invalid-UTF-8 JSON-string schema" do
      expect { @r = verify('{"type":"string"}'.encode("UTF-16LE")) }.not_to raise_error
      expect(@r[0]).to be(false)
    end
  end

  describe "RE2 pattern gate" do
    it "rejects ECMA features RE2 lacks (lookaround, backrefs, atomic, possessive)" do
      ["(?!foo)bar", "(?<=a)b", '(a)\\1', "(?>ab)", "a*+"].each do |pattern|
        expect(verify({ "type" => "string", "pattern" => pattern })[0]).to be(false)
      end
    end

    it "accepts RE2-compatible patterns (incl. (?:) and both named-group syntaxes)" do
      ["^[a-z]+$", "(?:ab)+", "(?<n>a)b", "(?P<n>a)b", "[(?=]+"].each do |pattern|
        expect(verify({ "type" => "string", "pattern" => pattern })[0]).to be(true)
      end
    end

    it "applies the RE2 gate to patternProperties keys too" do
      expect(verify({ "patternProperties" => { "(?!x)" => { "type" => "integer" } } })[0]).to be(false)
    end

    # The gate is the actual RE2 engine (re2 gem) — these are constructs where Ruby's Regexp and RE2
    # disagree, so they confirm the engine is RE2, not Onigmo.
    it "matches RE2 (not Ruby) on engine-specific constructs" do
      # RE2 accepts, Ruby rejects:
      ["\\xff", "[\\d-z]"].each { |p| expect(verify({ "pattern" => p })[0]).to be(true) }
      # RE2 rejects, Ruby accepts:
      ["\\x{110000}", "a**", "a{2}{3}"].each { |p| expect(verify({ "pattern" => p })[0]).to be(false) }
      # \C: C++ RE2 accepts but Go's regexp (gojsonschema) rejects -> filtered. An escaped backslash before
      # C (\\C = literal backslash + literal C) is NOT a \C escape and stays valid (pins the possessive
      # backslash-run scan in GO_REJECTED_ESCAPE).
      expect(verify({ "pattern" => "\\Cx" })[0]).to be(false)
      expect(verify({ "pattern" => "\\\\Cx" })[0]).to be(true)
    end
  end

  describe "$ref resolution (matches gojsonschema)" do
    it "is valid when an in-document fragment ref resolves, and suppresses sibling keywords" do
      expect(verify({ "definitions" => { "a" => {} }, "$ref" => "#/definitions/a" })[0]).to be(true)
      # a fragment ref replaces the node, so an invalid sibling is ignored
      expect(verify({ "definitions" => { "a" => {} }, "$ref" => "#/definitions/a", "type" => "bogus" })[0]).to be(true)
    end

    it "is invalid when a fragment ref does not resolve or points at a non-schema node" do
      expect(verify({ "definitions" => { "a" => {} }, "$ref" => "#/definitions/zzz" })[0]).to be(false)
      expect(verify({ "x" => 5, "$ref" => "#/x" })[0]).to be(false)
      expect(verify({ "$ref" => "#/" })[0]).to be(false)
    end

    it "is invalid for an external or relative ref" do
      expect(verify({ "$ref" => "https://example.com/s" })[0]).to be(false)
      expect(verify({ "$ref" => "foo.json" })[0]).to be(false)
    end

    it "treats a root ref (# or empty) as valid but does NOT suppress siblings" do
      expect(verify({ "$ref" => "#" })[0]).to be(true)
      expect(verify({ "$ref" => "" })[0]).to be(true)
      expect(verify({ "$ref" => "#", "type" => "bogus" })[0]).to be(false)
    end

    it "validates the resolved target and a definitions sibling, suppressing other siblings" do
      # invalid resolved target -> invalid (even under an unknown keyword)
      expect(verify({ "$ref" => "#/a/b", "a" => { "b" => { "type" => "foo" } } })[0]).to be(false)
      # a definitions sibling is still validated on a ref node
      expect(verify({ "$ref" => "#/x", "x" => { "type" => "string" },
                      "definitions" => { "b" => { "type" => "foo" } } })[0]).to be(false)
      # a non-definitions sibling is suppressed
      expect(verify({ "$ref" => "#/definitions/a", "definitions" => { "a" => {} },
                      "minLength" => "x" })[0]).to be(true)
    end

    it "tolerates self-referential and mutual ref cycles (no infinite loop)" do
      expect(verify({ "definitions" => { "a" => { "$ref" => "#/definitions/a" } } })[0]).to be(true)
      expect(verify({ "definitions" => { "a" => { "$ref" => "#/definitions/b" },
                                         "b" => { "$ref" => "#/definitions/a" } },
                      "$ref" => "#/definitions/a" })[0]).to be(true)
    end

    it "validates a cyclic ref node's own keywords (a cycle does not suppress, unlike a fresh fragment)" do
      expect(verify({ "$ref" => "#/definitions/a",
                      "definitions" => { "a" => { "$ref" => "#/definitions/a", "minLength" => -1 } } })[0])
        .to be(false)
    end
  end

  describe "RE2 inline flags (RE2 allows i/m/s/U; Ruby allows i/m/x — disjoint)" do
    it "accepts RE2 flag letters Ruby's parser rejects" do
      ["(?s)a", "(?U)a", "(?imsU)a", "(?i:a)"].each do |pattern|
        expect(verify({ "pattern" => pattern })[0]).to be(true)
      end
    end

    it "rejects Ruby/Onigmo flags and groups RE2 lacks" do
      ["(?x)a", "(?u)a", "(?x:a)", "(?#comment)abc", "(?~foo)"].each do |pattern|
        expect(verify({ "pattern" => pattern })[0]).to be(false)
      end
    end
  end

  describe "totality on malformed encodings" do
    it "does not raise (returns [false, ...]) on an invalid-UTF-8 pattern" do
      bad = (+"\xFF").force_encoding("UTF-8")
      expect { @r = verify({ "pattern" => bad }) }.not_to raise_error
      expect(@r[0]).to be(false)
    end
  end

  describe "registration" do
    it "registers the builtin" do
      expect(registry.registered?("json.verify_schema")).to be(true)
    end
  end
end
# rubocop:enable Metrics/BlockLength
