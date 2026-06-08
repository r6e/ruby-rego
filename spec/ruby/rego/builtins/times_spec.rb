# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
# All expected values were verified against `opa eval` 1.17.

RSpec.describe "time parsing builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  def call(name, arg)
    registry.call(name, [arg])
  end

  def value(name, arg)
    result = call(name, arg)
    result.is_a?(Ruby::Rego::UndefinedValue) ? :undef : result.to_ruby
  end

  describe "time.parse_rfc3339_ns" do
    it "parses UTC, offset, and fractional timestamps to nanoseconds" do
      expect(value("time.parse_rfc3339_ns", "2024-03-15T12:30:45Z")).to eq(1_710_505_845_000_000_000)
      expect(value("time.parse_rfc3339_ns", "2024-03-15T12:30:45+05:00")).to eq(1_710_487_845_000_000_000)
      expect(value("time.parse_rfc3339_ns", "2024-03-15T12:30:45.123456789Z")).to eq(1_710_505_845_123_456_789)
    end

    it "accepts a fraction of any length, truncating to nanoseconds" do
      expect(value("time.parse_rfc3339_ns", "2024-03-15T12:30:45.5Z")).to eq(1_710_505_845_500_000_000)
      expect(value("time.parse_rfc3339_ns", "2024-03-15T12:30:45.123456789999Z")).to eq(1_710_505_845_123_456_789)
    end

    it "is undefined for a missing/malformed zone, lowercase T/Z, or trailing dot" do
      ["2024-03-15T12:30:45", "2024-03-15t12:30:45Z", "2024-03-15T12:30:45z",
       "2024-03-15T12:30:45+0500", "2024-03-15T12:30:45+05", "2024-03-15T12:30:45.Z"].each do |s|
        expect(value("time.parse_rfc3339_ns", s)).to eq(:undef)
      end
    end

    it "is undefined for an invalid calendar date/time (Ruby's Time would normalise it)" do
      ["2024-02-30T00:00:00Z", "2024-13-01T00:00:00Z", "2024-03-15T24:00:00Z",
       "2024-03-15T12:30:60Z", "2023-02-29T00:00:00Z"].each do |s|
        expect(value("time.parse_rfc3339_ns", s)).to eq(:undef)
      end
    end

    it "accepts a leap day in a leap year" do
      expect(value("time.parse_rfc3339_ns", "2024-02-29T00:00:00Z")).to eq(1_709_164_800_000_000_000)
    end

    it "accepts out-of-range offset fields up to 24h/60m and applies them (matching Go), not raising" do
      # Go accepts an offset hour up to 24 and minute up to 60, each independently.
      expect(value("time.parse_rfc3339_ns", "2024-06-15T12:00:00+24:60")).to eq(1_718_362_800_000_000_000)
      expect(value("time.parse_rfc3339_ns", "2024-06-15T12:00:00+00:60")).to eq(1_718_449_200_000_000_000)
      # A negative out-of-range offset is applied with the opposite sign.
      expect(value("time.parse_rfc3339_ns", "2024-06-15T12:00:00-24:60")).to eq(1_718_542_800_000_000_000)
      # Beyond those per-field limits → undefined (no crash).
      expect(value("time.parse_rfc3339_ns", "2024-06-15T12:00:00+25:00")).to eq(:undef)
      expect(value("time.parse_rfc3339_ns", "2024-06-15T12:00:00+00:61")).to eq(:undef)
    end

    it "is undefined outside the int64-nanosecond range, a non-string, and a non-date" do
      expect(value("time.parse_rfc3339_ns", "1500-01-01T00:00:00Z")).to eq(:undef)
      expect(value("time.parse_rfc3339_ns", "2300-01-01T00:00:00Z")).to eq(:undef)
      expect(value("time.parse_rfc3339_ns", "not-a-date")).to eq(:undef)
      expect(call("time.parse_rfc3339_ns", 42)).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "time.parse_duration_ns" do
    it "parses signed, multi-unit, and fractional Go durations" do
      expect(value("time.parse_duration_ns", "1h30m")).to eq(5_400_000_000_000)
      expect(value("time.parse_duration_ns", "-2h45m")).to eq(-9_900_000_000_000)
      expect(value("time.parse_duration_ns", "1.5h")).to eq(5_400_000_000_000)
      expect(value("time.parse_duration_ns", "100us")).to eq(100_000)
      expect(value("time.parse_duration_ns", "100µs")).to eq(100_000)
      expect(value("time.parse_duration_ns", "0")).to eq(0)
    end

    it "parses the d/w/y extension (24h/168h/8760h, including fractions)" do
      expect(value("time.parse_duration_ns", "1d")).to eq(86_400_000_000_000)
      expect(value("time.parse_duration_ns", "1w")).to eq(604_800_000_000_000)
      expect(value("time.parse_duration_ns", "1y")).to eq(31_536_000_000_000_000)
      expect(value("time.parse_duration_ns", "1d12h")).to eq(129_600_000_000_000)
      expect(value("time.parse_duration_ns", "1.5d")).to eq(129_600_000_000_000)
    end

    it "allows the negative int64 minimum but rejects the positive overflow" do
      expect(value("time.parse_duration_ns", "-9223372036854775808ns")).to eq(-9_223_372_036_854_775_808)
      expect(value("time.parse_duration_ns", "9223372036854775808ns")).to eq(:undef)
    end

    it "is undefined for empty, unit-less, or malformed input, and a non-string" do
      ["", "5", "abc", "h", "1.5.2h", "1h30"].each do |s|
        expect(value("time.parse_duration_ns", s)).to eq(:undef)
      end
      expect(call("time.parse_duration_ns", 42)).to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end
# rubocop:enable Metrics/BlockLength
