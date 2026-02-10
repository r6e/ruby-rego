# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe "aggregate builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  it "counts arrays, objects, sets, and strings" do
    expect(registry.call("count", [[1, 2, 3]]).to_ruby).to eq(3)
    expect(registry.call("count", [{ "a" => 1, "b" => 2 }]).to_ruby).to eq(2)
    expect(registry.call("count", [Set.new(%w[a b])]).to_ruby).to eq(2)
    expect(registry.call("count", ["rego"]).to_ruby).to eq(4)
  end

  it "sums numeric arrays" do
    expect(registry.call("sum", [[1, 2, 3]]).to_ruby).to eq(6)
  end

  it "raises for non-numeric sum elements" do
    result = registry.call("sum", [[1, "x"]])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "computes max and min for numeric arrays" do
    expect(registry.call("max", [[2, 5, 3]]).to_ruby).to eq(5)
    expect(registry.call("min", [[2, 5, 3]]).to_ruby).to eq(2)
  end

  it "raises for empty max and min" do
    max_result = registry.call("max", [[]])
    min_result = registry.call("min", [[]])

    expect(max_result).to be_a(Ruby::Rego::UndefinedValue)
    expect(min_result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "evaluates all and any using Rego truthiness" do
    expect(registry.call("all", [[true, "x"]]).to_ruby).to be(true)
    expect(registry.call("all", [[true, nil]]).to_ruby).to be(false)
    expect(registry.call("any", [[nil, false, 1]]).to_ruby).to be(true)
    expect(registry.call("any", [[]]).to_ruby).to be(false)
  end

  it "allows repeated registration" do
    expect { Ruby::Rego::Builtins::Aggregates.register! }.not_to raise_error
    expect { Ruby::Rego::Builtins::Aggregates.register! }.not_to raise_error
  end
end

# rubocop:enable Metrics/BlockLength
