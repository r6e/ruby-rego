# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe "regex builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  describe "regex.match" do
    it "performs an unanchored match" do
      expect(registry.call("regex.match", ["a.c", "abc"]).to_ruby).to be(true)
      expect(registry.call("regex.match", ["[0-9]+", "id-42"]).to_ruby).to be(true)
    end

    it "respects anchors" do
      expect(registry.call("regex.match", ["^abc$", "xabcx"]).to_ruby).to be(false)
    end

    it "is undefined for an invalid pattern" do
      expect(registry.call("regex.match", ["a(b", "x"])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a non-string argument" do
      expect(registry.call("regex.match", [1, "x"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "regex.is_valid" do
    it "returns true for a valid pattern and false for an invalid one" do
      expect(registry.call("regex.is_valid", ["a(b)c"]).to_ruby).to be(true)
      expect(registry.call("regex.is_valid", ["a(b"]).to_ruby).to be(false)
    end

    # NOTE: patterns compile with Ruby's engine (Onigmo), not Go's RE2, so
    # lookahead is considered valid here whereas OPA (RE2) reports false.
    it "considers Ruby-valid lookahead patterns valid (documented RE2 divergence)" do
      expect(registry.call("regex.is_valid", ["(?=foo)"]).to_ruby).to be(true)
    end
  end

  describe "regex.split" do
    it "keeps trailing and leading empty segments (matching OPA)" do
      expect(registry.call("regex.split", [",", "a,b,"]).to_ruby).to eq(["a", "b", ""])
      expect(registry.call("regex.split", [",", ",a,b"]).to_ruby).to eq(["", "a", "b"])
    end

    it "splits on a character class" do
      expect(registry.call("regex.split", ["[,;]", "a,b;c"]).to_ruby).to eq(%w[a b c])
    end

    it "handles a zero-width pattern like OPA (no trailing empty)" do
      expect(registry.call("regex.split", ["x*", "abc"]).to_ruby).to eq(%w[a b c])
    end

    it "returns a single empty string for empty input (matching OPA)" do
      expect(registry.call("regex.split", [",", ""]).to_ruby).to eq([""])
    end

    it "returns the whole string when the pattern does not match" do
      expect(registry.call("regex.split", %w[z abc]).to_ruby).to eq(%w[abc])
    end

    it "is undefined for an invalid pattern" do
      expect(registry.call("regex.split", ["a(b", "x"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "regex.find_n" do
    it "returns the first n full matches" do
      expect(registry.call("regex.find_n", ["[0-9]+", "a1b22c333", 2]).to_ruby).to eq(%w[1 22])
    end

    it "returns all matches when n is negative" do
      expect(registry.call("regex.find_n", ["[0-9]+", "a1b22c333", -1]).to_ruby).to eq(%w[1 22 333])
    end

    it "returns an empty array when n is zero" do
      expect(registry.call("regex.find_n", ["[0-9]+", "a1b2", 0]).to_ruby).to eq([])
    end

    it "returns the full match even when the pattern has groups" do
      expect(registry.call("regex.find_n", ["a(b)c", "abc abc", -1]).to_ruby).to eq(%w[abc abc])
    end

    it "is undefined for an invalid pattern" do
      expect(registry.call("regex.find_n", ["a(b", "x", -1])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end

# rubocop:enable Metrics/BlockLength
