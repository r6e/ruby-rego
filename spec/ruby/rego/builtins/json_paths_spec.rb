# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
# Expected values verified against `opa eval` 1.17 (runtime/input path for type edges).
RSpec.describe "json path builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  let(:doc) { { "a" => { "b" => 1, "c" => 2 }, "d" => [10, 20, 30], "e" => "keep" } }

  def filter(document, paths)
    result = registry.call("json.filter", [document, paths])
    result.is_a?(Ruby::Rego::UndefinedValue) ? :undef : result.to_ruby
  end

  def remove(document, paths)
    result = registry.call("json.remove", [document, paths])
    result.is_a?(Ruby::Rego::UndefinedValue) ? :undef : result.to_ruby
  end

  describe "json.filter" do
    it "keeps only the listed paths (string and array form)" do
      expect(filter(doc, ["a/b", "e"])).to eq("a" => { "b" => 1 }, "e" => "keep")
      expect(filter(doc, [%w[a c], %w[d 1]])).to eq("a" => { "c" => 2 }, "d" => [20])
      expect(filter(doc, ["a"])).to eq("a" => { "b" => 1, "c" => 2 })
      expect(filter(doc, [])).to eq({})
    end

    it "keeps a partially-present path as an empty container" do
      expect(filter(doc, ["a/z", "nope"])).to eq("a" => {})
      expect(filter(doc, ["d/9"])).to eq("d" => [])  # out-of-range index
      expect(filter(doc, ["d/x"])).to eq("d" => [])  # non-numeric index
    end

    it "keeps a scalar whole when a path tries to descend into it" do
      expect(filter(doc, ["e/x"])).to eq("e" => "keep")
    end

    it "merges overlapping paths (a terminal path keeps the whole subtree, in either order)" do
      expect(filter(doc, ["a", "a/b"])).to eq("a" => { "b" => 1, "c" => 2 })
      expect(filter(doc, ["a/b", "a"])).to eq("a" => { "b" => 1, "c" => 2 })
      expect(filter(doc, ["a/b", "a/c"])).to eq("a" => { "b" => 1, "c" => 2 })
    end

    it "applies JSON-pointer escaping to string paths but treats array segments literally" do
      esc = { "a/b" => 1, "c~d" => 2 }
      expect(filter(esc, ["a~1b"])).to eq("a/b" => 1)
      expect(filter(esc, ["c~0d"])).to eq("c~d" => 2)
      expect(filter(esc, [["a/b"]])).to eq("a/b" => 1)
    end

    it "is undefined for a non-object document or non-array paths" do
      expect(filter([1, 2], ["0"])).to eq(:undef)
      expect(filter(doc, "a")).to eq(:undef)
      expect(filter(doc, [5])).to eq(:undef) # a path element must be a string or array
    end
  end

  describe "json.remove" do
    it "removes the listed paths (string and array form)" do
      expect(remove(doc, ["a/b", "e"])).to eq("a" => { "c" => 2 }, "d" => [10, 20, 30])
      expect(remove(doc, ["a"])).to eq("d" => [10, 20, 30], "e" => "keep")
      expect(remove(doc, [])).to eq(doc)
    end

    it "removes an array element and reindexes" do
      expect(remove(doc, [%w[d 1]])).to eq("a" => { "b" => 1, "c" => 2 }, "d" => [10, 30], "e" => "keep")
    end

    it "removes multiple array indices against the original positions" do
      arr_doc = { "arr" => [10, 20, 30, 40] }
      expect(remove(arr_doc, [%w[arr 0], %w[arr 1]])).to eq("arr" => [30, 40])
      expect(remove(arr_doc, ["arr/1", "arr/3"])).to eq("arr" => [10, 30])
    end

    it "removes a leaf inside an array element without removing the element" do
      nested = { "arr" => [{ "x" => 1 }, { "x" => 2 }] }
      expect(remove(nested, ["arr/0/x"])).to eq("arr" => [{}, { "x" => 2 }])
    end

    it "is a no-op for a missing path, out-of-range index, or scalar descent" do
      expect(remove(doc, ["x/y"])).to eq(doc)
      expect(remove(doc, ["d/9"])).to eq(doc)
      expect(remove(doc, ["e/x"])).to eq(doc)
    end

    it "is undefined for a non-object document or non-array paths" do
      expect(remove([1, 2], ["0"])).to eq(:undef)
      expect(remove(doc, "a")).to eq(:undef)
    end
  end
end
# rubocop:enable Metrics/BlockLength
