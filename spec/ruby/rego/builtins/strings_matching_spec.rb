# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
RSpec.describe "strings.replace_n / any_prefix_match / any_suffix_match" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  describe "strings.replace_n" do
    # Each expected value below was verified against `opa eval` 1.17 and encodes a
    # specific rule of OPA's (Go strings.Replacer) semantics: keys are applied in
    # ascending sort order, single left-to-right pass, replacements are not rescanned,
    # and the earliest-sorted key that prefixes the remainder wins on a tie.
    it "replaces each distinct key (basic)" do
      expect(registry.call("strings.replace_n", [{ "a" => "1", "b" => "2" }, "abcab"]).to_ruby)
        .to eq("12c12")
    end

    it "does not rescan replaced text" do
      expect(registry.call("strings.replace_n", [{ "a" => "b", "b" => "c" }, "a"]).to_ruby)
        .to eq("b")
    end

    it "gives the earliest-sorted key priority on a tie (a beats aa)" do
      expect(registry.call("strings.replace_n", [{ "aa" => "X", "a" => "Y" }, "aaa"]).to_ruby)
        .to eq("YYY")
    end

    it "gives a shorter prefix key priority over a longer one (ab beats abc)" do
      expect(registry.call("strings.replace_n", [{ "ab" => "X", "abc" => "Y" }, "abc"]).to_ruby)
        .to eq("Xc")
    end

    it "interleaves an empty key with a non-empty key" do
      expect(registry.call("strings.replace_n", [{ "" => "X", "a" => "Y" }, "a"]).to_ruby)
        .to eq("XYX")
    end

    it "inserts an empty-key replacement at every position" do
      expect(registry.call("strings.replace_n", [{ "" => "X" }, "ab"]).to_ruby)
        .to eq("XaXbX")
    end

    it "replaces by Unicode codepoint" do
      expect(registry.call("strings.replace_n", [{ "é" => "e" }, "café"]).to_ruby)
        .to eq("cafe")
    end

    it "returns the empty string for empty input" do
      expect(registry.call("strings.replace_n", [{ "a" => "X" }, ""]).to_ruby).to eq("")
    end

    it "is undefined for a non-string value in the patterns object" do
      expect(registry.call("strings.replace_n", [{ "a" => 1 }, "a"]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a non-string key in the patterns object" do
      expect(registry.call("strings.replace_n", [{ 1 => "x" }, "a"]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined when the patterns argument is not an object" do
      expect(registry.call("strings.replace_n", %w[a a]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined when the value argument is not a string" do
      expect(registry.call("strings.replace_n", [{ "a" => "b" }, 1]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "strings.any_prefix_match" do
    it "matches a string search against a string base (search starts with base)" do
      expect(registry.call("strings.any_prefix_match", %w[foobar foo]).to_ruby).to be(true)
    end

    it "does not match when the base is longer than the search" do
      expect(registry.call("strings.any_prefix_match", %w[foo foobar]).to_ruby).to be(false)
    end

    it "matches across array arguments" do
      expect(registry.call("strings.any_prefix_match", [%w[foo bar], %w[xy ba]]).to_ruby).to be(true)
    end

    it "matches with a set base" do
      expect(registry.call("strings.any_prefix_match", [Set["foo", "bar"], Set["fo"]]).to_ruby).to be(true)
    end

    it "treats an empty base string as a prefix of everything" do
      expect(registry.call("strings.any_prefix_match", ["foo", ""]).to_ruby).to be(true)
    end

    it "is false when the search collection is empty" do
      expect(registry.call("strings.any_prefix_match", [[], "foo"]).to_ruby).to be(false)
    end

    it "is false when the base collection is empty" do
      expect(registry.call("strings.any_prefix_match", ["foo", []]).to_ruby).to be(false)
    end

    it "is undefined for a non-string element in an array" do
      expect(registry.call("strings.any_prefix_match", [["foo", 1], "fo"]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a non-string element in a set" do
      expect(registry.call("strings.any_prefix_match", [Set["foo", 1], "fo"]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined when an argument is an object" do
      expect(registry.call("strings.any_prefix_match", [{ "a" => "b" }, "fo"]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "strings.any_suffix_match" do
    it "matches a string search against a string base (search ends with base)" do
      expect(registry.call("strings.any_suffix_match", %w[foobar bar]).to_ruby).to be(true)
    end

    it "matches across array arguments" do
      expect(registry.call("strings.any_suffix_match", [%w[foo bar], %w[oo zz]]).to_ruby).to be(true)
    end

    it "is false when nothing matches" do
      expect(registry.call("strings.any_suffix_match", [%w[foo bar], %w[zz]]).to_ruby).to be(false)
    end

    it "is undefined for a non-string element" do
      expect(registry.call("strings.any_suffix_match", [["foo", 1], "oo"]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end
# rubocop:enable Metrics/BlockLength
