# frozen_string_literal: true

require "spec_helper"

# GoNumberFormat renders shortest digits the way Go's strconv / math/big 'g' verb does. Expected forms
# verified against `opa eval` 1.17 (the FloatToNumber 'g' path).
RSpec.describe Ruby::Rego::GoNumberFormat do
  describe ".shortest_digits" do
    it "parses fixed and scientific shortest strings into [digits, point]" do
      expect(described_class.shortest_digits("0.33333333333333333334")).to eq(["33333333333333333334", 0])
      expect(described_class.shortest_digits("3E-300")).to eq(["3", -299])
      expect(described_class.shortest_digits("123456.5")).to eq(["1234565", 6])
      expect(described_class.shortest_digits("0")).to eq(["0", 1])
    end

    it "ignores a leading sign" do
      expect(described_class.shortest_digits("-1.5")).to eq(["15", 1])
    end
  end

  describe ".render" do
    it "uses fixed notation for exponents in [-4, 6)" do
      expect(described_class.render(*described_class.shortest_digits("0.0001"), false)).to eq("0.0001")
      expect(described_class.render(*described_class.shortest_digits("123456.5"), false)).to eq("123456.5")
    end

    it "uses scientific notation below -4 and at/above 6, signed and zero-padded to two digits" do
      expect(described_class.render(*described_class.shortest_digits("0.00001"), false)).to eq("1e-05")
      expect(described_class.render(*described_class.shortest_digits("1234567.5"), false)).to eq("1.2345675e+06")
    end

    it "prefixes a negative sign" do
      expect(described_class.render(*described_class.shortest_digits("1.5"), true)).to eq("-1.5")
    end
  end
end
