# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
RSpec.describe "glob builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  def match(pattern, delimiters, value)
    registry.call("glob.match", [pattern, delimiters, value]).to_ruby
  end

  # Every expected value below was verified against `opa eval` 1.17.
  describe "glob.match wildcards" do
    it "matches a literal pattern" do
      expect(match("abc", ["."], "abc")).to be(true)
      expect(match("abc", ["."], "abd")).to be(false)
    end

    it "anchors the whole string" do
      expect(match("ab", ["."], "abc")).to be(false)
      expect(match("bc", ["."], "abc")).to be(false)
    end

    it "matches * within a segment but not across a delimiter" do
      expect(match("*.example.com", ["."], "api.example.com")).to be(true)
      expect(match("*.example.com", ["."], "a.b.example.com")).to be(false)
    end

    it "matches ** across delimiters (superstar)" do
      expect(match("**.example.com", ["."], "a.b.example.com")).to be(true)
    end

    it "matches * and ** against an empty span" do
      expect(match("a*b", ["."], "ab")).to be(true)
      expect(match("a**b", ["."], "ab")).to be(true)
    end

    it "matches ? as a single non-delimiter character" do
      expect(match("a?c", ["."], "abc")).to be(true)
      expect(match("a?c", ["."], "a.c")).to be(false)
    end
  end

  describe "glob.match delimiters" do
    it "treats null as no delimiters (* matches everything)" do
      expect(match("a*c", nil, "a.c")).to be(true)
      expect(match("*", nil, "a.b")).to be(true)
    end

    it "treats an empty array as the default delimiter '.'" do
      expect(match("a*c", [], "a.c")).to be(false)
      expect(match("a*c", [], "abc")).to be(true)
    end

    it "uses the provided delimiters" do
      expect(match("a*c", [","], "a.c")).to be(true)
      expect(match("a*c", [","], "a,c")).to be(false)
    end

    it "supports multiple delimiters" do
      expect(match("a*c", [".", ":"], "a.c")).to be(false)
      expect(match("a*c", [".", ":"], "a:c")).to be(false)
      expect(match("a*c", [".", ":"], "axc")).to be(true)
    end

    it "is undefined for a multi-character delimiter" do
      expect(registry.call("glob.match", ["a", ["xy"], "a"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "glob.match character classes" do
    it "matches a class and a range" do
      expect(match("[a-c]at", ["."], "bat")).to be(true)
      expect(match("[a-c]at", ["."], "hat")).to be(false)
    end

    it "negates a class with !" do
      expect(match("[!a-c]at", ["."], "hat")).to be(true)
      expect(match("[!a-c]at", ["."], "bat")).to be(false)
    end

    it "matches a delimiter character listed in a class" do
      expect(match("x[.]y", ["."], "x.y")).to be(true)
    end

    it "honors a backslash escape inside a class" do
      expect(match('[\\]]', ["."], "]")).to be(true)
      expect(match('[a\\-z]', ["."], "-")).to be(true)
      expect(match('[a\\-z]', ["."], "b")).to be(false)
    end

    it "treats && in a class as literal characters (not regex intersection)" do
      expect(match("[a&&b]", ["."], "&")).to be(true)
      expect(match("[a&&b]", ["."], "a")).to be(true)
    end
  end

  describe "glob.match brace alternation" do
    it "matches a simple alternation" do
      expect(match("{cat,bat}", ["."], "bat")).to be(true)
      expect(match("{cat,bat}", ["."], "rat")).to be(false)
    end

    it "matches nested braces" do
      expect(match("{a,b{c,d}}", ["."], "bd")).to be(true)
      expect(match("{a,b{c,d}}", ["."], "a")).to be(true)
    end

    it "matches braces containing wildcards" do
      expect(match("{*.com,*.org}", ["."], "x.org")).to be(true)
      expect(match("{*.com,*.org}", ["."], "x.net")).to be(false)
    end
  end

  describe "glob.match escaping" do
    it "treats an escaped metacharacter as a literal" do
      expect(match('a\\*b', ["."], "a*b")).to be(true)
      expect(match('a\\*b', ["."], "axb")).to be(false)
    end
  end

  # ruby-rego implements correct glob semantics rather than reproducing known bugs in
  # OPA's matcher (gobwas/glob). These cases return a useful result here but are wrong
  # or undefined in OPA. See gobwas/glob issues #41, #47, #66.
  describe "glob.match (intentional corrections of known OPA/gobwas bugs)" do
    it "uses standard character-class semantics (gobwas #47)" do
      # OPA's restrictive grammar rejects multi-range classes (undefined) and reads a
      # range mixed with literals as literal characters; standard glob handles both.
      expect(match("[A-Za-z]", ["."], "B")).to be(true) # OPA: undefined
      expect(match("[A-Za-z]", ["."], "7")).to be(false)
      expect(match("[a-z0-9]", ["."], "5")).to be(true) # OPA: undefined
      expect(match("[a-zA-Z0-9]", ["."], "Z")).to be(true)
      expect(match("[a0-9]", ["."], "5")).to be(true)   # OPA: false (reads a,0,-,9 literally)
    end

    it "matches non-ASCII characters under ? consistently by codepoint (gobwas #41)" do
      # OPA 1.17 matches [ö] and a standalone ?, but ? in a sequence still fails on
      # non-ASCII (both of these return false in OPA); this matches them by codepoint.
      expect(match("ångstr?m", ["."], "ångström")).to be(true)
      expect(match("a?c", ["."], "a😀c")).to be(true)
    end

    it "requires ? and negated classes to consume exactly one character" do
      # OPA returns true for these (it lets ? / [!..] match the empty string).
      expect(match("?", nil, "")).to be(false)
      expect(match("[!0-9]", nil, "")).to be(false)
    end
  end

  describe "glob.match invalid input" do
    it "is undefined for a non-string pattern" do
      expect(registry.call("glob.match", [123, ["."], "a"])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a malformed pattern (unclosed class)" do
      expect(registry.call("glob.match", ["[abc", ["."], "a"])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for pathologically deep brace nesting (DoS guard)" do
      pattern = "#{"{" * 5000}a#{"}" * 5000}"
      expect(registry.call("glob.match", [pattern, nil, "a"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "glob.quote_meta" do
    it "escapes glob metacharacters" do
      expect(registry.call("glob.quote_meta", ["*.domain.com"]).to_ruby).to eq('\\*.domain.com')
      expect(registry.call("glob.quote_meta", ["a*b?c[d]{e}"]).to_ruby).to eq('a\\*b\\?c\\[d\\]\\{e\\}')
    end

    it "leaves non-glob characters unescaped" do
      expect(registry.call("glob.quote_meta", ["a-b,c.d"]).to_ruby).to eq("a-b,c.d")
    end

    it "escapes a backslash" do
      expect(registry.call("glob.quote_meta", ['a\\b']).to_ruby).to eq('a\\\\b')
    end

    it "round-trips: match(quote_meta(s), d, s) is true for metacharacters" do
      raw = 'a*b?c[d]{e}\\f'
      quoted = registry.call("glob.quote_meta", [raw]).to_ruby
      expect(match(quoted, ["."], raw)).to be(true)
    end
  end

  it "allows repeated registration" do
    expect { Ruby::Rego::Builtins::Glob.register! }.not_to raise_error
  end
end
# rubocop:enable Metrics/BlockLength
