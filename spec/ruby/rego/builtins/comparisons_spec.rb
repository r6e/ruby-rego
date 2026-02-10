# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe "comparison builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  it "compares values with deep equality" do
    expect(registry.call("equal", [[1, 2], [1, 2]]).to_ruby).to be(true)
    expect(registry.call("equal", [Set.new([1, 2]), Set.new([2, 1])]).to_ruby).to be(true)
    expect(registry.call("equal", [{ "a" => [1] }, { "a" => [1] }]).to_ruby).to be(true)
  end

  it "converts strings to numbers" do
    expect(registry.call("to_number", ["42"]).to_ruby).to eq(42)
    expect(registry.call("to_number", ["3.5"]).to_ruby).to eq(3.5)
  end

  it "raises for invalid numeric strings" do
    result = registry.call("to_number", ["oops"])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "casts values to string" do
    expect(registry.call("cast_string", [true]).to_ruby).to eq("true")
    expect(registry.call("cast_string", [12]).to_ruby).to eq("12")
    expect(registry.call("cast_string", [nil]).to_ruby).to eq("null")
  end

  it "casts values to boolean" do
    expect(registry.call("cast_boolean", ["true"]).to_ruby).to be(true)
    expect(registry.call("cast_boolean", ["false"]).to_ruby).to be(false)
    expect(registry.call("cast_boolean", [1]).to_ruby).to be(true)
    expect(registry.call("cast_boolean", [0]).to_ruby).to be(false)
  end

  it "raises for invalid boolean casts" do
    yes_result = registry.call("cast_boolean", ["yes"])
    two_result = registry.call("cast_boolean", [2])

    expect(yes_result).to be_a(Ruby::Rego::UndefinedValue)
    expect(two_result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "casts arrays and sets" do
    expect(registry.call("cast_array", [Set.new([1, 2])]).to_ruby).to match_array([1, 2])
    expect(registry.call("cast_set", [[1, 2]]).to_ruby).to eq(Set.new([1, 2]))
  end

  it "raises for invalid array casts" do
    result = registry.call("cast_array", [{ "a" => 1 }])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "raises for invalid set casts" do
    result = registry.call("cast_set", [{ "a" => 1 }])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "casts objects" do
    expect(registry.call("cast_object", [{ "a" => 1 }]).to_ruby).to eq({ "a" => 1 })
  end

  it "raises for invalid object casts" do
    result = registry.call("cast_object", [[1]])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "allows repeated registration" do
    expect { Ruby::Rego::Builtins::Comparisons.register! }.not_to raise_error
    expect { Ruby::Rego::Builtins::Comparisons.register! }.not_to raise_error
  end
end

# rubocop:enable Metrics/BlockLength
