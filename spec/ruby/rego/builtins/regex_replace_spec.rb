# frozen_string_literal: true

require "timeout"

# rubocop:disable Metrics/BlockLength
RSpec.describe "regex.replace" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  def replace(string, pattern, value)
    registry.call("regex.replace", [string, pattern, value]).to_ruby
  end

  # Every expected value below was verified against `opa eval` 1.17. The replacement
  # value uses Go's Expand template syntax (`$1`, `${name}`, `$$`), not Ruby's.
  it "replaces all non-overlapping matches" do
    expect(replace("hello world", "o", "0")).to eq("hell0 w0rld")
    expect(replace("hello", "l+", "L")).to eq("heLo")
  end

  it "leaves the string unchanged when nothing matches" do
    expect(replace("abc", "x", "y")).to eq("abc")
  end

  it "expands numbered submatches" do
    expect(replace("2023-01-15", '(\d+)-(\d+)-(\d+)', "$3/$2/$1")).to eq("15/01/2023")
    expect(replace("abc", "(b)", "$1$1")).to eq("abbc")
  end

  it "expands $0 as the whole match" do
    expect(replace("abc", "(b)", "[$0]")).to eq("a[b]c")
  end

  it "parses a bare $name greedily and braces delimit it" do
    expect(replace("abc", "(b)", "$1x")).to eq("ac") # name "1x" -> unknown -> empty
    expect(replace("abc", "(b)", "${1}x")).to eq("abxc")  # group 1 + "x"
    expect(replace("abc", "(b)", "$10")).to eq("ac")      # group 10 -> out of range -> empty
    expect(replace("abc", "(b)", "${1}0")).to eq("ab0c")
  end

  it "expands $$ as a literal dollar sign" do
    expect(replace("abc", "b", "$$")).to eq("a$c")
    expect(replace("abc", "b", "$$1")).to eq("a$1c")
  end

  it "treats a $ not followed by a valid name as a literal" do
    expect(replace("abc", "b", "$")).to eq("a$c")
    expect(replace("abc", "(b)", "$-x")).to eq("a$-xc")
  end

  it "treats a backslash as a literal (templates use $, not Ruby's \\)" do
    expect(replace("x", "x", '\1')).to eq('\1')
  end

  it "expands an out-of-range numbered submatch to empty" do
    expect(replace("abc", "(b)", "$2")).to eq("ac")
  end

  it "treats a leading-zero numeric reference as an unknown named group (Go rule)" do
    expect(replace("abc", "(b)", "$01")).to eq("ac")    # "01" -> named -> unknown -> empty
    expect(replace("abc", "(b)", "$00")).to eq("ac")
    expect(replace("abc", "(b)", "$0")).to eq("abc")    # single 0 stays the whole match
  end

  it "does not rewrite (?P< that appears inside a character class" do
    # The named-group translation must not corrupt a class containing those literals.
    expect(replace("P", "[(?P<]", "Z")).to eq("Z")
  end

  it "reads a reference name as Unicode letters/digits (Go rule)" do
    # A Unicode name is consumed into the (unknown) reference and expands to empty.
    expect(replace("abc", "(b)", "$é")).to eq("ac")
    expect(replace("abc", "(b)", "${café}")).to eq("ac")
    expect(replace("abc", "(b)", "$１")).to eq("ac") # fullwidth digit -> named -> empty
  end

  it "expands an unknown named submatch to empty" do
    expect(replace("abc", "b", "$nope")).to eq("ac")
  end

  it "expands named submatches with Go (?P<name>) syntax" do
    expect(replace("foobar", "(?P<x>foo)", "[$x]")).to eq("[foo]bar")
    expect(replace("foobar", "(?P<x>foo)", "[${x}]")).to eq("[foo]bar")
    expect(replace("foo123", '(?P<w>[a-z]+)(?P<d>\d+)', "${d}-${w}")).to eq("123-foo")
  end

  it "numbers named and unnamed groups in one RE2-style space (mixed groups)" do
    # Onigmo would renumber when a named group is present; the name->index map keeps a
    # single left-to-right numbering, matching OPA/RE2.
    expect(replace("ab", "(?P<x>a)(b)", "$2-${x}")).to eq("b-a")
    expect(replace("abc", "(a)(?P<x>b)(c)", "$1$2$3")).to eq("abc")
  end

  it "supports digit-leading and duplicate names like RE2" do
    expect(replace("ab", "(?P<1a>a)(b)", "${1a}-$2")).to eq("a-b")
    expect(replace("ab", "(?P<dup>a)(?P<dup>b)", "${dup}")).to eq("a") # first occurrence
  end

  it "does not number a non-capturing (?:...) group" do
    expect(replace("xbc", "(?:x)(b)(c)", "$1")).to eq("b")
  end

  it "recognizes the RE2 (?<name>) synonym for (?P<name>)" do
    # RE2/OPA accept both; named and unnamed groups share one left-to-right numbering.
    expect(replace("xy", "(?<a>x)(?P<b>y)", "${a}|${b}|$1|$2")).to eq("x|y|x|y")
    expect(replace("xy", "(?<a>x)(y)", "$1$2")).to eq("xy")
  end

  it "does not treat lookbehind (?<=...) as a named group" do
    # `(?<=a)` is a lookbehind, not a capture; OPA (RE2) rejects lookbehind, but the gem
    # accepts it via Onigmo (documented superset). Either way it is not a named group, so
    # numbering is unaffected.
    expect(replace("ab", "(?<=a)(b)", "[$1]")).to eq("a[b]")
  end

  it "matches an empty pattern between every character" do
    expect(replace("abc", "", "-")).to eq("-a-b-c-")
  end

  it "skips a zero-width match immediately after a non-empty one (Go/RE2)" do
    # Ruby's gsub would emit the trailing empty match; Go/RE2 (and find_n/split here) skip it.
    expect(replace("abc", ".*", "X")).to eq("X")
    expect(replace("aaabbb", "a*", "X")).to eq("XbXbXbX")
    expect(replace("abc", "a|", "X")).to eq("XbXcX")
  end

  it "treats an unclosed or empty brace reference as a literal" do
    expect(replace("abc", "(b)", "${")).to eq("a${c")
    expect(replace("abc", "(b)", "${}")).to eq("a${}c")
  end

  it "is undefined for an invalid pattern" do
    expect(registry.call("regex.replace", ["abc", "(", "y"])).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "is undefined for a non-string argument" do
    expect(registry.call("regex.replace", ["a", "a", 1])).to be_a(Ruby::Rego::UndefinedValue)
    expect(registry.call("regex.replace", [1, "a", "b"])).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "is undefined for an invalid-encoding string (reaches only the Ruby API)" do
    bad = "\xFF\xFE".dup.force_encoding("UTF-8")
    expect(registry.call("regex.replace", [bad, "a", "x"])).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "is undefined when the expanded output would be too large (DoS guard)" do
    string = "a" * 50_000
    template = "$0" * 10_000
    expect(registry.call("regex.replace", [string, "a", template])).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "bounds a single match's expansion, not just the cumulative total (DoS guard)" do
    # One match whose template repeats a large whole-match must not build unboundedly.
    string = "a" * 100_000
    template = "$0" * 100_000
    expect(registry.call("regex.replace", [string, ".+", template])).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "bounds empty-reference work that produces no output (DoS guard)" do
    # Each out-of-range $9 resolves to "", so the output budget never trips, yet every
    # match still loops all template segments: matches x segments work with zero output.
    # The work budget must catch this in bounded time.
    string = "a" * 40_000
    template = "$9" * 20_000
    result = nil
    expect do
      Timeout.timeout(20) { result = registry.call("regex.replace", [string, "a", template]) }
    end.not_to raise_error
    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "still expands a legitimate large-but-bounded replacement" do
    string = "a" * 1_000
    result = registry.call("regex.replace", [string, "a", "[$0]"])
    expect(result.value).to eq("[a]" * 1_000)
  end

  it "rejects an over-length replacement template in O(1) (DoS guard)" do
    # A huge template is split into a char array (String#chars) before parsing — an
    # uninterruptible C call. Even with empty-resolving refs (no output, low work) it must
    # be rejected by the up-front length cap, not materialized.
    template = "${z}" * 8_000_000 # 32M chars, well over the source cap
    result = nil
    expect do
      Timeout.timeout(5) { result = registry.call("regex.replace", ["a", "a", template]) }
    end.not_to raise_error
    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "rejects an over-length pattern in O(1) (DoS guard)" do
    pattern = "a" * 8_000_000 # over the source cap; shared by every regex built-in
    result = nil
    expect do
      Timeout.timeout(5) { result = registry.call("regex.replace", ["a", pattern, "x"]) }
    end.not_to raise_error
    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "bounds aggregate match-scan cost across the loop (DoS guard)" do
    # A pattern that is cheap per match but does O(n) engine work per match over O(n)
    # matches is O(n^2): the per-match engine timeout resets each search, so only an
    # aggregate deadline across the gsub loop catches it. (Uses lookahead — a documented
    # Onigmo superset over RE2 — but the bound is on the loop, not the syntax.)
    string = "a" * 60_000
    result = nil
    expect do
      Timeout.timeout(15) { result = registry.call("regex.replace", [string, "(?=a*$)a", "x"]) }
    end.not_to raise_error
    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "preprocesses a degenerate (?P< pattern in linear time (no quadratic scan)" do
    # Many `(?P<` with no closing `>` must not trigger an O(n) rescan per occurrence
    # during named-group translation. The pattern fails to compile, so the result is
    # undefined — but it must arrive in bounded time, not after a quadratic burn.
    pattern = "(?P<" * 100_000
    result = nil
    expect do
      Timeout.timeout(10) { result = registry.call("regex.replace", ["abc", pattern, "x"]) }
    end.not_to raise_error
    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end
end
# rubocop:enable Metrics/BlockLength
