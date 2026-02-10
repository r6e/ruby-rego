# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe "collection builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  it "sorts arrays" do
    expect(registry.call("sort", [[3, 1, 2]]).to_ruby).to eq([1, 2, 3])
    expect(registry.call("sort", [%w[b a]]).to_ruby).to eq(%w[a b])
  end

  it "raises for mixed sort types" do
    result = registry.call("sort", [[1, "a"]])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "concatenates arrays" do
    expect(registry.call("array.concat", [[1, 2], [3]]).to_ruby).to eq([1, 2, 3])
  end

  it "slices arrays" do
    expect(registry.call("array.slice", [[1, 2, 3, 4], 1, 3]).to_ruby).to eq([2, 3])
    expect(registry.call("array.slice", [[1, 2, 3], 3, 3]).to_ruby).to eq([])
  end

  it "raises for invalid slice indices" do
    result = registry.call("array.slice", [[1], -1, 1])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "gets object keys with defaults" do
    expect(registry.call("object.get", [{ "a" => 1 }, "a", 0]).to_ruby).to eq(1)
    expect(registry.call("object.get", [{ "a" => 1 }, "b", 0]).to_ruby).to eq(0)
  end

  it "returns object keys" do
    expect(registry.call("object.keys", [{ "a" => 1, "b" => 2 }]).to_ruby)
      .to match_array(%w[a b])
  end

  it "removes keys from objects" do
    object = { "a" => 1, "b" => 2, "c" => 3 }
    expect(registry.call("object.remove", [object, ["b"]]).to_ruby)
      .to eq({ "a" => 1, "c" => 3 })
    expect(registry.call("object.remove", [object, Set.new(%w[a c])]).to_ruby)
      .to eq({ "b" => 2 })
  end

  it "unions sets and objects" do
    expect(registry.call("union", [Set.new([1, 2]), Set.new([2, 3])]).to_ruby)
      .to eq(Set.new([1, 2, 3]))
    expect(registry.call("union", [{ "a" => 1 }, { "b" => 2 }]).to_ruby)
      .to eq({ "a" => 1, "b" => 2 })
  end

  it "raises for union conflicts" do
    result = registry.call("union", [{ "a" => 1 }, { "a" => 2 }])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "raises for union type mismatch" do
    result = registry.call("union", [Set.new([1]), { "a" => 1 }])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "intersects and diffs sets" do
    expect(registry.call("intersection", [Set.new([1, 2]), Set.new([2, 3])]).to_ruby)
      .to eq(Set.new([2]))
    expect(registry.call("set_diff", [Set.new([1, 2]), Set.new([2, 3])]).to_ruby)
      .to eq(Set.new([1]))
  end

  it "allows repeated registration" do
    expect { Ruby::Rego::Builtins::Collections.register! }.not_to raise_error
    expect { Ruby::Rego::Builtins::Collections.register! }.not_to raise_error
  end

  it "builds empty sets" do
    result = registry.call("set", [])

    expect(result.to_ruby).to eq(Set.new)
  end

  it "converts arrays to sets" do
    result = registry.call("set", [[1, 2]])

    expect(result.to_ruby).to eq(Set.new([1, 2]))
  end

  it "returns undefined for invalid set arguments" do
    result = registry.call("set", [{ "a" => 1 }])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end
end

# rubocop:enable Metrics/BlockLength
