# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe "type builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  it "checks string values" do
    expect(registry.call("is_string", ["hello"]).to_ruby).to be(true)
    expect(registry.call("is_string", [123]).to_ruby).to be(false)
  end

  it "checks number values" do
    expect(registry.call("is_number", [123]).to_ruby).to be(true)
    expect(registry.call("is_number", ["123"]).to_ruby).to be(false)
  end

  it "checks boolean values" do
    expect(registry.call("is_boolean", [true]).to_ruby).to be(true)
    expect(registry.call("is_boolean", [nil]).to_ruby).to be(false)
  end

  it "checks array values" do
    expect(registry.call("is_array", [[1, 2]]).to_ruby).to be(true)
    expect(registry.call("is_array", ["not array"]).to_ruby).to be(false)
  end

  it "checks object values" do
    expect(registry.call("is_object", [{ "a" => 1 }]).to_ruby).to be(true)
    expect(registry.call("is_object", [[1, 2]]).to_ruby).to be(false)
  end

  it "checks set values" do
    expect(registry.call("is_set", [Set.new([1, 2])]).to_ruby).to be(true)
    expect(registry.call("is_set", [[1, 2]]).to_ruby).to be(false)
  end

  it "checks null values" do
    expect(registry.call("is_null", [nil]).to_ruby).to be(true)
    expect(registry.call("is_null", [false]).to_ruby).to be(false)
  end

  it "returns type names" do
    expect(registry.call("type_name", [nil]).to_ruby).to eq("null")
    expect(registry.call("type_name", [[1, 2]]).to_ruby).to eq("array")
    expect(registry.call("type_name", [{ "a" => 1 }]).to_ruby).to eq("object")
    expect(registry.call("type_name", [Set.new([1, 2])]).to_ruby).to eq("set")
    expect(registry.call("type_name", [registry.call("object.keys", [{ "a" => 1 }])]).to_ruby).to eq("set")
  end

  it "allows repeated registration" do
    expect { Ruby::Rego::Builtins::Types.register! }.not_to raise_error
    expect { Ruby::Rego::Builtins::Types.register! }.not_to raise_error
  end
end

# rubocop:enable Metrics/BlockLength
