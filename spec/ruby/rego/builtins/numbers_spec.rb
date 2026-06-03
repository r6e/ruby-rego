# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe "numeric builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  describe "abs" do
    it "returns the absolute value, preserving int vs float" do
      expect(registry.call("abs", [-3]).to_ruby).to eq(3)
      expect(registry.call("abs", [-3.5]).to_ruby).to eq(3.5)
      expect(registry.call("abs", [4]).to_ruby).to eq(4)
    end

    it "normalizes an integer-valued float result to an integer (matching OPA)" do
      expect(registry.call("abs", [-2.0]).to_ruby).to eql(2)
    end

    it "is undefined for a non-number argument" do
      expect(registry.call("abs", ["x"])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a non-finite argument" do
      expect(registry.call("abs", [Float::INFINITY])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "round" do
    it "rounds half away from zero (matching OPA)" do
      expect(registry.call("round", [2.5]).to_ruby).to eq(3)
      expect(registry.call("round", [-2.5]).to_ruby).to eq(-3)
      expect(registry.call("round", [2.4]).to_ruby).to eq(2)
      expect(registry.call("round", [0.5]).to_ruby).to eq(1)
      expect(registry.call("round", [-0.5]).to_ruby).to eq(-1)
    end

    it "returns an integer and accepts integer input" do
      expect(registry.call("round", [2.0]).to_ruby).to eql(2)
      expect(registry.call("round", [3]).to_ruby).to eql(3)
    end

    it "is undefined for a non-number argument" do
      expect(registry.call("round", ["x"])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined (not a crash) for a non-finite argument" do
      expect(registry.call("round", [Float::INFINITY])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("round", [Float::NAN])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "ceil" do
    it "rounds toward positive infinity" do
      expect(registry.call("ceil", [2.1]).to_ruby).to eql(3)
      expect(registry.call("ceil", [-2.1]).to_ruby).to eql(-2)
      expect(registry.call("ceil", [3]).to_ruby).to eql(3)
    end

    it "is undefined for a non-number argument" do
      expect(registry.call("ceil", [[]])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "floor" do
    it "rounds toward negative infinity" do
      expect(registry.call("floor", [2.9]).to_ruby).to eql(2)
      expect(registry.call("floor", [-2.1]).to_ruby).to eql(-3)
      expect(registry.call("floor", [3]).to_ruby).to eql(3)
    end

    it "is undefined for a non-number argument" do
      expect(registry.call("floor", ["x"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "numbers.range" do
    it "produces an inclusive ascending range" do
      expect(registry.call("numbers.range", [1, 3]).to_ruby).to eq([1, 2, 3])
      expect(registry.call("numbers.range", [-1, 1]).to_ruby).to eq([-1, 0, 1])
    end

    it "produces a descending range when the start exceeds the end" do
      expect(registry.call("numbers.range", [3, 1]).to_ruby).to eq([3, 2, 1])
    end

    it "produces a single-element range when bounds are equal" do
      expect(registry.call("numbers.range", [2, 2]).to_ruby).to eq([2])
    end

    it "accepts integer-valued floats as bounds (matching OPA)" do
      expect(registry.call("numbers.range", [1, 3.0]).to_ruby).to eq([1, 2, 3])
    end

    it "is undefined when a bound is not an integer value (matching OPA)" do
      expect(registry.call("numbers.range", [1.5, 3])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a non-number bound" do
      expect(registry.call("numbers.range", ["a", 3])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined when the range exceeds the maximum size (allocation guard)" do
      max = Ruby::Rego::Builtins::Numbers::MAX_RANGE_SIZE
      expect(registry.call("numbers.range", [1, max + 1])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("numbers.range", [-1, max])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end

# rubocop:enable Metrics/BlockLength
