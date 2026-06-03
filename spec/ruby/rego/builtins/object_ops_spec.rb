# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe "object builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  describe "object.union" do
    it "deep-merges nested objects with the second operand winning conflicts" do
      result = registry.call(
        "object.union",
        [{ "a" => 1, "b" => { "x" => 1 } }, { "b" => { "y" => 2 }, "c" => 3 }]
      )
      expect(result.to_ruby).to eq("a" => 1, "b" => { "x" => 1, "y" => 2 }, "c" => 3)
    end

    it "lets the second operand win a scalar conflict" do
      expect(registry.call("object.union", [{ "a" => 1 }, { "a" => 2 }]).to_ruby).to eq("a" => 2)
    end

    it "replaces across types (object vs scalar) with the second operand" do
      expect(registry.call("object.union", [{ "a" => { "x" => 1 } }, { "a" => 5 }]).to_ruby).to eq("a" => 5)
      expect(registry.call("object.union", [{ "a" => 5 }, { "a" => { "x" => 1 } }]).to_ruby).to eq("a" => { "x" => 1 })
    end

    it "is undefined for a non-object operand" do
      expect(registry.call("object.union", [{ "a" => 1 }, 5])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "replaces array values rather than merging them (matching OPA)" do
      expect(registry.call("object.union", [{ "a" => [1, 2] }, { "a" => [3, 4] }]).to_ruby).to eq("a" => [3, 4])
    end

    it "preserves non-string keys (Rego allows them)" do
      expect(registry.call("object.union", [{ 1 => "a" }, { 2 => "b", 1 => "c" }]).to_ruby).to eq(1 => "c", 2 => "b")
    end

    it "does not mutate its operands" do
      left = Ruby::Rego::ObjectValue.new("a" => Ruby::Rego::ObjectValue.new("x" => 1))
      right = Ruby::Rego::ObjectValue.new("a" => Ruby::Rego::ObjectValue.new("y" => 2))
      registry.call("object.union", [left, right])
      expect(left.to_ruby).to eq("a" => { "x" => 1 })
      expect(right.to_ruby).to eq("a" => { "y" => 2 })
    end
  end

  describe "object.union_n" do
    it "folds a deep union across an array of objects (later wins)" do
      result = registry.call("object.union_n", [[{ "a" => 1 }, { "b" => 2 }, { "a" => 3 }]])
      expect(result.to_ruby).to eq("a" => 3, "b" => 2)
    end

    it "returns an empty object for an empty array" do
      expect(registry.call("object.union_n", [[]]).to_ruby).to eq({})
    end

    it "is undefined when an element is not an object" do
      expect(registry.call("object.union_n", [[{ "a" => 1 }, 5]])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined when the argument is not an array" do
      expect(registry.call("object.union_n", [5])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "object.filter" do
    it "keeps only the named keys from an array of keys" do
      expect(registry.call("object.filter", [{ "a" => 1, "b" => 2, "c" => 3 }, %w[a c]]).to_ruby)
        .to eq("a" => 1, "c" => 3)
    end

    it "accepts a set of keys" do
      expect(registry.call("object.filter", [{ "a" => 1, "b" => 2 }, Set.new(["a"])]).to_ruby).to eq("a" => 1)
    end

    it "accepts an object of keys (values ignored)" do
      expect(registry.call("object.filter", [{ "a" => 1, "b" => 2 }, { "a" => "ignored" }]).to_ruby).to eq("a" => 1)
    end

    it "skips keys absent from the object and preserves nested values" do
      expect(registry.call("object.filter", [{ "a" => { "x" => 1 }, "b" => 2 }, %w[a z]]).to_ruby)
        .to eq("a" => { "x" => 1 })
    end

    it "returns an empty object when filtering an empty object" do
      expect(registry.call("object.filter", [{}, %w[a]]).to_ruby).to eq({})
    end

    it "is undefined for a non-object first argument" do
      expect(registry.call("object.filter", [5, %w[a]])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "object.remove (object-keys support)" do
    it "accepts an object as the keys collection (matching OPA)" do
      expect(registry.call("object.remove", [{ "a" => 1, "b" => 2 }, { "a" => "x" }]).to_ruby).to eq("b" => 2)
    end
  end
end

# rubocop:enable Metrics/BlockLength
