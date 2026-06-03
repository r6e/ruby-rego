# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe "string extra builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  describe "replace" do
    it "replaces all literal (non-regex) occurrences" do
      expect(registry.call("replace", ["a.b.c", ".", "-"]).to_ruby).to eq("a-b-c")
      expect(registry.call("replace", ["a+b", "+", "X"]).to_ruby).to eq("aXb")
    end

    it "replaces non-overlapping occurrences" do
      expect(registry.call("replace", %w[aaa aa b]).to_ruby).to eq("ba")
    end

    it "inserts the replacement around every position for an empty search (matching OPA)" do
      expect(registry.call("replace", ["abc", "", "X"]).to_ruby).to eq("XaXbXcX")
    end

    it "is undefined for a non-string argument" do
      expect(registry.call("replace", [1, ".", "-"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "trim_prefix / trim_suffix" do
    it "removes a present prefix and leaves an absent one" do
      expect(registry.call("trim_prefix", %w[foobar foo]).to_ruby).to eq("bar")
      expect(registry.call("trim_prefix", %w[foobar xxx]).to_ruby).to eq("foobar")
    end

    it "removes a present suffix" do
      expect(registry.call("trim_suffix", %w[foobar bar]).to_ruby).to eq("foo")
    end
  end

  describe "strings.reverse" do
    it "reverses by character, including multibyte" do
      expect(registry.call("strings.reverse", ["abc"]).to_ruby).to eq("cba")
      expect(registry.call("strings.reverse", ["résumé"]).to_ruby).to eq("émusér")
    end
  end

  describe "strings.count" do
    it "counts non-overlapping occurrences" do
      expect(registry.call("strings.count", %w[banana a]).to_ruby).to eq(3)
      expect(registry.call("strings.count", %w[aaa aa]).to_ruby).to eq(1)
    end

    it "counts an empty search as length + 1 (matching OPA)" do
      expect(registry.call("strings.count", ["abc", ""]).to_ruby).to eq(4)
    end
  end

  describe "indexof_n" do
    it "returns all non-overlapping match indices" do
      expect(registry.call("indexof_n", %w[aXbXc X]).to_ruby).to eq([1, 3])
    end

    it "returns an empty array when there is no match" do
      expect(registry.call("indexof_n", %w[abc z]).to_ruby).to eq([])
    end

    it "is undefined for an empty search string (matching OPA)" do
      expect(registry.call("indexof_n", ["abc", ""])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end

# rubocop:enable Metrics/BlockLength
