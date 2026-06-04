# frozen_string_literal: true

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

  it "expands an unknown named submatch to empty" do
    expect(replace("abc", "b", "$nope")).to eq("ac")
  end

  it "expands named submatches with Go (?P<name>) syntax" do
    expect(replace("foobar", "(?P<x>foo)", "[$x]")).to eq("[foo]bar")
    expect(replace("foobar", "(?P<x>foo)", "[${x}]")).to eq("[foo]bar")
    expect(replace("foo123", '(?P<w>[a-z]+)(?P<d>\d+)', "${d}-${w}")).to eq("123-foo")
  end

  it "matches an empty pattern between every character" do
    expect(replace("abc", "", "-")).to eq("-a-b-c-")
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
end
# rubocop:enable Metrics/BlockLength
