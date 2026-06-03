# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
RSpec.describe "bits builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  # Every expected value below was verified against `opa eval` 1.17. Ruby's
  # &/|/^/~/<</>> use two's-complement infinite precision, matching Go's big.Int.
  describe "bits.and" do
    it "ands two non-negative integers" do
      expect(registry.call("bits.and", [12, 10]).to_ruby).to eq(8)
    end

    it "ands two negative integers (two's complement)" do
      expect(registry.call("bits.and", [-4, -2]).to_ruby).to eq(-4)
    end

    it "accepts integer-valued floats" do
      expect(registry.call("bits.and", [12.0, 10]).to_ruby).to eq(8)
    end

    it "is undefined for a non-integer float" do
      expect(registry.call("bits.and", [12.5, 10])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a non-number argument" do
      expect(registry.call("bits.and", ["x", 1])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "bits.or" do
    it "ors two integers" do
      expect(registry.call("bits.or", [12, 10]).to_ruby).to eq(14)
    end

    it "ors two negative integers" do
      expect(registry.call("bits.or", [-4, -2]).to_ruby).to eq(-2)
    end
  end

  describe "bits.xor" do
    it "xors two integers" do
      expect(registry.call("bits.xor", [12, 10]).to_ruby).to eq(6)
    end

    it "xors two negative integers" do
      expect(registry.call("bits.xor", [-4, -2]).to_ruby).to eq(2)
    end
  end

  describe "bits.negate" do
    it "negates zero to -1" do
      expect(registry.call("bits.negate", [0]).to_ruby).to eq(-1)
    end

    it "negates a positive integer" do
      expect(registry.call("bits.negate", [12]).to_ruby).to eq(-13)
    end

    it "negates -1 to 0" do
      expect(registry.call("bits.negate", [-1]).to_ruby).to eq(0)
    end

    it "is undefined for a non-integer float" do
      expect(registry.call("bits.negate", [2.5])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "bits.lsh" do
    it "shifts left" do
      expect(registry.call("bits.lsh", [1, 4]).to_ruby).to eq(16)
    end

    it "shifts a negative value left" do
      expect(registry.call("bits.lsh", [-8, 2]).to_ruby).to eq(-32)
    end

    it "accepts an integer-valued float shift count" do
      expect(registry.call("bits.lsh", [1, 4.0]).to_ruby).to eq(16)
    end

    it "is undefined for a negative shift count" do
      expect(registry.call("bits.lsh", [8, -1])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a non-integer shift count" do
      expect(registry.call("bits.lsh", [1, 4.5])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "shifts zero regardless of the (in-range) shift amount" do
      expect(registry.call("bits.lsh", [0, 1000]).to_ruby).to eq(0)
    end

    it "is undefined when the result would exceed the size cap (DoS guard)" do
      expect(registry.call("bits.lsh", [1, 50_000_000])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "bits.rsh" do
    it "shifts right" do
      expect(registry.call("bits.rsh", [256, 4]).to_ruby).to eq(16)
    end

    it "arithmetic-shifts a negative value right" do
      expect(registry.call("bits.rsh", [-8, 1]).to_ruby).to eq(-4)
    end

    it "shifts a value entirely out to zero" do
      expect(registry.call("bits.rsh", [8, 100]).to_ruby).to eq(0)
    end

    it "is undefined for a negative shift count" do
      expect(registry.call("bits.rsh", [8, -1])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  it "allows repeated registration" do
    expect { Ruby::Rego::Builtins::Bits.register! }.not_to raise_error
  end
end
# rubocop:enable Metrics/BlockLength
