# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
# All expected values below were verified against `opa eval` 1.17.
RSpec.describe "units builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  def parse(string)
    registry.call("units.parse", [string])
  end

  def parse_bytes(string)
    registry.call("units.parse_bytes", [string])
  end

  describe "units.parse" do
    it "parses plain numbers, returning integers and floats" do
      expect(parse("10").to_ruby).to eq(10)
      expect(parse("10.5").to_ruby).to eq(10.5)
      expect(parse("-5").to_ruby).to eq(-5)
    end

    it "applies SI (decimal) suffixes, case-insensitive except m/M" do
      expect(parse("10K").to_ruby).to eq(10_000)
      expect(parse("10k").to_ruby).to eq(10_000)
      expect(parse("10M").to_ruby).to eq(10_000_000)
      expect(parse("10G").to_ruby).to eq(10_000_000_000)
      expect(parse("1.5K").to_ruby).to eq(1500)
    end

    it "treats lowercase m as milli and uppercase M as mega" do
      expect(parse("10m").to_ruby).to eq(0.01)
      expect(parse("10M").to_ruby).to eq(10_000_000)
      # OPA's milli uses float64(0.001), so an exact multiple of 1000 yields a float, not an int.
      expect(parse("1000m").to_ruby).to eq(1.0)
      expect(parse("1000m").to_ruby).to be_a(Float)
    end

    it "removes embedded double-quotes from the value, matching OPA" do
      expect(parse(%(1"0K)).to_ruby).to eq(10_000)
    end

    it "applies binary suffixes (trailing i), case-insensitive on the first letter" do
      expect(parse("10Ki").to_ruby).to eq(10_240)
      expect(parse("10ki").to_ruby).to eq(10_240)
      expect(parse("10Mi").to_ruby).to eq(10_485_760)
      expect(parse("10mi").to_ruby).to eq(10_485_760) # mebi, not milli-i
      expect(parse("10Gi").to_ruby).to eq(10_737_418_240)
    end

    it "rounds a non-integer result to 10 decimals (matching OPA's big.Rat output)" do
      expect(parse("10.123456789012m").to_ruby).to eq(0.0101234568)
    end

    it "accepts scientific notation and the exa suffix" do
      expect(parse("1e3K").to_ruby).to eq(1_000_000)
      expect(parse("10e").to_ruby).to eq(10_000_000_000_000_000_000)
    end

    it "is undefined for spaces, unknown units, bad amounts, non-strings, or huge exponents" do
      expect(parse(" 10K ")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse("10Q")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse("10kb")).to be_a(Ruby::Rego::UndefinedValue) # kb is parse_bytes-only
      expect(parse("abc")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse("")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse("K")).to be_a(Ruby::Rego::UndefinedValue) # no amount
      expect(parse(42)).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse("1e1000000K")).to be_a(Ruby::Rego::UndefinedValue) # > 6 exponent digits
    end
  end

  describe "units.parse_bytes" do
    it "parses byte quantities, truncating toward zero to an integer" do
      expect(parse_bytes("10").to_ruby).to eq(10)
      expect(parse_bytes("10kb").to_ruby).to eq(10_000)
      expect(parse_bytes("10KB").to_ruby).to eq(10_000) # case-insensitive
      expect(parse_bytes("10k").to_ruby).to eq(10_000)
      expect(parse_bytes("1.5kib").to_ruby).to eq(1536)
      expect(parse_bytes("10.7").to_ruby).to eq(10) # truncated
      expect(parse_bytes("-5kb").to_ruby).to eq(-5000)
    end

    it "supports the full SI and binary suffix set" do
      expect(parse_bytes("10MB").to_ruby).to eq(10_000_000)
      expect(parse_bytes("10Mi").to_ruby).to eq(10_485_760)
      expect(parse_bytes("10GiB").to_ruby).to eq(10_737_418_240)
      expect(parse_bytes("1TiB").to_ruby).to eq(1024**4)
    end

    it "is undefined for a bare b, spaces, unknown units, bad amounts, or non-strings" do
      expect(parse_bytes("10b")).to be_a(Ruby::Rego::UndefinedValue) # bare b is not a unit
      expect(parse_bytes(" 10kb")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse_bytes("abc")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse_bytes("")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse_bytes(42)).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "uses exact arithmetic, unlike OPA's big.Float (documented divergence)" do
      # OPA's parse_bytes uses big.Float and truncates 0.001mb to 999; we compute exactly
      # (1000), matching what OPA's own big.Rat-based units.parse("0.001M") returns.
      expect(parse_bytes("0.001mb").to_ruby).to eq(1000)
    end
  end
end
# rubocop:enable Metrics/BlockLength
