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
      expect(value("time.parse_rfc3339_ns", "0000-01-01T00:00:00Z")).to eq(:undef) # extreme years, no crash
      expect(value("time.parse_rfc3339_ns", "9999-12-31T23:59:59Z")).to eq(:undef)
      expect(value("time.parse_rfc3339_ns", "not-a-date")).to eq(:undef)
      expect(call("time.parse_rfc3339_ns", 42)).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "returns undefined (not a crash) when Time.utc raises RangeError, as on a 32-bit time_t build" do
      allow(Time).to receive(:utc).and_raise(RangeError)
      expect(value("time.parse_rfc3339_ns", "2000-01-01T00:00:00Z")).to eq(:undef)
    end
  end

  describe "time.date / time.clock / time.weekday" do
    let(:ns) { 1_710_505_845_123_456_789 } # 2024-03-15T12:30:45.123…Z (a Friday)

    it "decomposes a bare ns operand in UTC" do
      expect(value("time.date", ns)).to eq([2024, 3, 15])
      expect(value("time.clock", ns)).to eq([12, 30, 45])
      expect(value("time.weekday", ns)).to eq("Friday")
    end

    it "applies an IANA timezone from the [ns, tz] form" do
      expect(value("time.clock", [ns, "America/New_York"])).to eq([8, 30, 45]) # UTC-4 (EDT)
      expect(value("time.clock", [ns, "Asia/Kolkata"])).to eq([18, 0, 45]) # UTC+5:30
      expect(value("time.date", [ns, "Pacific/Kiritimati"])).to eq([2024, 3, 16]) # UTC+14, next day
    end

    it "treats \"\" and \"UTC\" as UTC and handles a DST transition instant" do
      expect(value("time.clock", [ns, ""])).to eq([12, 30, 45])
      expect(value("time.clock", [ns, "UTC"])).to eq([12, 30, 45])
      # 2024-03-10 07:00:00Z is the US spring-forward: 02:00 EST jumps to 03:00 EDT.
      expect(value("time.clock", [1_710_054_000_000_000_000, "America/New_York"])).to eq([3, 0, 0])
    end

    it "handles the epoch, pre-epoch (sub-second floor), and the int64 bounds" do
      expect(value("time.date", 0)).to eq([1970, 1, 1])
      expect(value("time.weekday", 0)).to eq("Thursday")
      expect(value("time.date", -1)).to eq([1969, 12, 31])
      expect(value("time.clock", -1)).to eq([23, 59, 59]) # negative ns floors toward the second
      expect(value("time.clock", -500_000_000)).to eq([23, 59, 59])
      expect(value("time.date", 9_223_372_036_854_775_807)).to eq([2262, 4, 11])
      expect(value("time.clock", 9_223_372_036_854_775_807)).to eq([23, 47, 16])
      expect(value("time.date", -9_223_372_036_854_775_808)).to eq([1677, 9, 21])
    end

    it "returns undefined (not a crash) when Time.at raises RangeError, as on a 32-bit time_t build" do
      allow(Time).to receive(:at).and_raise(RangeError)
      expect(call("time.date", [ns, "UTC"])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "resolves \"Local\" against the process timezone" do
      original = ENV.fetch("TZ", nil)
      ENV["TZ"] = "America/New_York"
      expect(value("time.clock", [ns, "Local"])).to eq([8, 30, 45]) # 12:30:45Z in EDT
    ensure
      ENV["TZ"] = original
    end

    it "accepts a third (layout) element and further elements, ignoring them" do
      expect(value("time.date", [ns, "UTC", "ignored-layout"])).to eq([2024, 3, 15])
      expect(value("time.date", [ns, "UTC", "lay", "extra"])).to eq([2024, 3, 15])
    end

    it "is undefined for an empty array, bad/non-string tz, fractional or oversized ns, or wrong type" do
      [[], [ns, "Not/AZone"], [ns, 123], [ns, "UTC", 9], 1.5, [1.5, "UTC"],
       [9_223_372_036_854_775_808, "UTC"], "x", true].each do |arg|
        expect(call("time.date", arg)).to be_a(Ruby::Rego::UndefinedValue)
      end
    end
  end

  describe "time.format" do
    let(:ns) { 1_710_505_845_123_456_789 } # 2024-03-15T12:30:45.123…Z (a Friday)

    def fmt(operand)
      r = registry.call("time.format", [operand])
      r.is_a?(Ruby::Rego::UndefinedValue) ? :undef : r.to_ruby
    end

    it "defaults to RFC3339Nano and applies the operand's timezone" do
      expect(fmt(ns)).to eq("2024-03-15T12:30:45.123456789Z")
      expect(fmt([ns])).to eq("2024-03-15T12:30:45.123456789Z") # single-element array → UTC
      expect(fmt([ns, "America/New_York"])).to eq("2024-03-15T08:30:45.123456789-04:00")
    end

    it "uses a named layout constant or a literal Go reference-time layout" do
      expect(fmt([ns, "UTC", "RFC3339"])).to eq("2024-03-15T12:30:45Z")
      expect(fmt([ns, "UTC", "2006-01-02 15:04:05"])).to eq("2024-03-15 12:30:45")
      expect(fmt([ns, "UTC", "Mon Jan _2 03:04:05 PM 2006"])).to eq("Fri Mar 15 12:30:45 PM 2024")
    end

    it "matches Go's Z-for-UTC, numeric-offset, and zone-abbreviation rendering" do
      expect(fmt([ns, "UTC", "2006-01-02T15:04:05Z07:00"])).to eq("2024-03-15T12:30:45Z")
      expect(fmt([ns, "Asia/Kolkata", "-0700 MST"])).to eq("+0530 IST")
      expect(fmt([ns, "Etc/GMT+5", "MST"])).to eq("-05") # numeric IANA abbreviation
    end

    it "trims a .999 fraction's trailing zeros (and the separator when zero), keeps .000 fixed" do
      expect(fmt([1_710_505_845_100_000_000, "UTC", "05.999"])).to eq("45.1")
      expect(fmt([1_710_505_845_000_000_000, "UTC", "05.999"])).to eq("45")
      expect(fmt([1_710_505_845_100_000_000, "UTC", "05.000"])).to eq("45.100")
    end

    it "is undefined for an unknown zone or a wrong-typed operand" do
      expect(fmt([ns, "Bad/Zone", "RFC3339"])).to eq(:undef)
      expect(registry.call("time.format", ["x"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "time.add_date" do
    def add_date(value, years, months, days)
      r = registry.call("time.add_date", [value, years, months, days])
      r.is_a?(Ruby::Rego::UndefinedValue) ? :undef : r.to_ruby
    end

    it "adds years/months/days, normalising overflow forward like Go's time.Date" do
      # 2024-01-31 + 1 month -> Mar 2 (Feb 31 rolls forward, not clamped to Feb 29).
      expect(add_date(1_706_659_200_000_000_000, 0, 1, 0)).to eq(1_709_337_600_000_000_000)
      # 2024-02-29 + 1 year -> 2025-03-01 (Feb 29 2025 doesn't exist).
      expect(add_date(1_709_164_800_000_000_000, 1, 0, 0)).to eq(1_740_787_200_000_000_000)
      expect(add_date(0, 0, 0, 0)).to eq(0)
      # pre-epoch (1900-01-01 + 1 month) — negative ns sub-second handling.
      expect(add_date(-2_208_988_800_000_000_000, 0, 1, 0)).to eq(-2_206_310_400_000_000_000)
    end

    it "re-anchors the wall clock in the operand's zone, resolving DST gaps/overlaps like Go" do
      # +1mo lands the wall clock 02:30 in the NY spring-forward gap -> Go's post-transition offset.
      expect(add_date([1_707_550_200_000_000_000, "America/New_York"], 0, 1, 0)).to eq(1_710_052_200_000_000_000)
      # +1mo lands 01:30 in the NY fall-back overlap -> Go's first occurrence.
      expect(add_date([1_727_933_400_000_000_000, "America/New_York"], 0, 1, 0)).to eq(1_730_611_800_000_000_000)
    end

    it "is undefined for an out-of-int64 result, a non-integer count, or an unknown zone" do
      expect(add_date(9_000_000_000_000_000_000, 1000, 0, 0)).to eq(:undef)
      expect(add_date(1_710_505_845_000_000_000, 0, 0, 1.5)).to eq(:undef)
      expect(add_date([1_710_505_845_000_000_000, "Bad/Zone"], 0, 1, 0)).to eq(:undef)
    end

    it "resolves a \"Local\" DST overlap like Go (first occurrence), not POSIX mktime (standard)" do
      original = ENV.fetch("TZ", nil)
      ENV["TZ"] = "America/New_York"
      # +1mo lands 01:30 in the fall-back overlap → Go's EDT (first) occurrence, not EST.
      expect(add_date([1_727_933_400_000_000_000, "Local"], 0, 1, 0)).to eq(1_730_611_800_000_000_000)
    ensure
      ENV["TZ"] = original
    end
  end

  describe "time.diff" do
    let(:a) { 1_710_505_845_000_000_000 } # 2024-03-15 12:30:45Z
    let(:b) { 1_700_000_000_000_000_000 } # 2023-11-14 22:13:20Z

    def diff(arg1, arg2)
      registry.call("time.diff", [arg1, arg2]).then { |r| r.is_a?(Ruby::Rego::UndefinedValue) ? :undef : r.to_ruby }
    end

    it "returns the non-negative [y, mo, d, h, mi, s] difference, symmetric in argument order" do
      expect(diff(a, b)).to eq([0, 4, 0, 14, 17, 25])
      expect(diff(b, a)).to eq([0, 4, 0, 14, 17, 25])
    end

    it "is all-zeros for identical instants and sub-second differences" do
      expect(diff(a, a)).to eq([0, 0, 0, 0, 0, 0])
      expect(diff(a + 1, a)).to eq([0, 0, 0, 0, 0, 0])
    end

    it "decomposes both instants in the first operand's timezone" do
      # Same pair, different first-operand zone → different hour component.
      expect(diff([a, "UTC"], [b, "Asia/Tokyo"])).to eq([0, 4, 0, 14, 17, 25])
      expect(diff([a, "America/New_York"], [b, "Asia/Tokyo"])).to eq([0, 4, 0, 15, 17, 25])
    end

    it "borrows correctly across a month boundary (end-of-month day borrow)" do
      # 2024-03-01T00:00:00Z minus 2024-02-29T12:00:00Z → 12h, borrowing from the 29-day Feb.
      expect(diff(1_709_251_200_000_000_000, 1_709_208_000_000_000_000)).to eq([0, 0, 0, 12, 0, 0])
    end

    it "is undefined for a wrong-typed operand or an unknown timezone on either side" do
      [[a, "x"], ["x", a], [[a, "Bad/Zone"], b], [a, [b, "Bad/Zone"]],
       [1.5, a], [a, 1.5], [[], a], [a, []]].each do |arg1, arg2|
        expect(registry.call("time.diff", [arg1, arg2])).to be_a(Ruby::Rego::UndefinedValue)
      end
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

  describe "time.parse_ns" do
    def parse_ns(layout, value)
      result = registry.call("time.parse_ns", [layout, value])
      result.is_a?(Ruby::Rego::UndefinedValue) ? :undef : result.to_ruby
    end

    # [layout, value, expected_ns] verified byte-for-byte against `TZ=UTC opa eval` 1.17
    # (nil == undefined). Zone abbreviations (MST/PST/GMT/ABC...) resolve to a 0 offset under
    # the UTC-deterministic policy documented in times/parse.rb; only explicit numeric offsets
    # and `Z` shift the instant. Out-of-int64-ns results (year 0, year 9999) are undefined.
    [
        ["Mon Jan _2 15:04:05 2006", "Mon Jan _2 15:04:05 2006", nil],
        ["Mon Jan _2 15:04:05 MST 2006", "Mon Jan _2 15:04:05 MST 2006", nil],
        ["Mon Jan 02 15:04:05 -0700 2006", "Mon Jan 02 15:04:05 -0700 2006", 1136239445000000000],
        ["02 Jan 06 15:04 MST", "02 Jan 06 15:04 MST", 1136214240000000000],
        ["02 Jan 06 15:04 -0700", "02 Jan 06 15:04 -0700", 1136239440000000000],
        ["Monday, 02-Jan-06 15:04:05 MST", "Monday, 02-Jan-06 15:04:05 MST", 1136214245000000000],
        ["Mon, 02 Jan 2006 15:04:05 MST", "Mon, 02 Jan 2006 15:04:05 MST", 1136214245000000000],
        ["Mon, 02 Jan 2006 15:04:05 -0700", "Mon, 02 Jan 2006 15:04:05 -0700", 1136239445000000000],
        ["2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05Z07:00", nil],
        ["2006-01-02T15:04:05.999999999Z07:00", "2006-01-02T15:04:05.999999999Z07:00", nil],
        ["RFC3339", "2024-03-10T12:30:45Z", 1710073845000000000],
        ["RFC3339Nano", "2024-03-10T12:30:45Z", 1710073845000000000],
        ["2006-01-02", "2024-03-10", 1710028800000000000],
        ["2006-01-02", "2024-02-29", 1709164800000000000],
        ["2006-01-02", "2024-12-31", 1735603200000000000],
        ["2006-01-02", "1970-01-01", 0],
        ["2006-01-02", "2024-3-10", nil],
        ["2006-01-02", "2024-13-01", nil],
        ["2006-01-02", "2024-00-10", nil],
        ["2006-01-02", "2024-02-30", nil],
        ["2006-01-02", "2023-02-29", nil],
        ["2006-01-02", "2024-03-00", nil],
        ["2006-01-02", "2024-03-32", nil],
        ["2006-01-02", "0000-01-01", nil],
        ["2006-01-02", "9999-12-31", nil],
        ["2006-01-02", "24-03-10", nil],
        ["2006-1-2", "2024-3-10", 1710028800000000000],
        ["2006-1-2", "2024-03-10", 1710028800000000000],
        ["2006-1-2", "2024-12-5", 1733356800000000000],
        ["06-01-02", "24-03-10", 1710028800000000000],
        ["06-01-02", "69-03-10", -25660800000000000],
        ["06-01-02", "68-03-10", 3098563200000000000],
        ["06-01-02", "99-12-31", 946598400000000000],
        ["06-01-02", "00-01-01", 946684800000000000],
        ["2006-01-02T15:04:05Z07:00", "2024-03-10T12:30:45Z", 1710073845000000000],
        ["2006-01-02T15:04:05Z07:00", "2024-03-10T12:30:45-05:00", 1710091845000000000],
        ["2006-01-02T15:04:05Z07:00", "2024-03-10T12:30:45+09:00", 1710041445000000000],
        ["2006-01-02T15:04:05Z07:00", "2024-03-10T00:00:00Z", 1710028800000000000],
        ["2006-01-02T15:04:05Z07:00", "2024-03-10T24:00:00Z", nil],
        ["2006-01-02T15:04:05Z07:00", "2024-03-10T23:60:00Z", nil],
        ["2006-01-02T15:04:05Z07:00", "2024-03-10T23:00:60Z", nil],
        ["2006-01-02T15:04:05Z07:00", "2024-03-10T12:30:45+14:00", 1710023445000000000],
        ["2006-01-02 15:04:05", "2024-03-10 12:30:45", 1710073845000000000],
        ["2006-01-02 15:04:05", "2024-03-10 00:00:00", 1710028800000000000],
        ["2006-01-02 15:04:05", "2024-03-10 23:59:59", 1710115199000000000],
        ["2006-01-02T15:04:05.999999999Z07:00", "2024-03-10T12:30:45.5Z", 1710073845500000000],
        ["2006-01-02T15:04:05.999999999Z07:00", "2024-03-10T12:30:45Z", 1710073845000000000],
        ["2006-01-02T15:04:05.999999999Z07:00", "2024-03-10T12:30:45.123456789Z", 1710073845123456789],
        ["2006-01-02T15:04:05.999999999Z07:00", "2024-03-10T12:30:45.999999999-05:00", 1710091845999999999],
        ["Mon Jan _2 15:04:05 2006", "Sun Mar 10 12:30:45 2024", 1710073845000000000],
        ["Mon Jan _2 15:04:05 2006", "Wed Mar 10 12:30:45 2024", 1710073845000000000],
        ["Mon Jan _2 15:04:05 2006", "Mon Jan  2 03:04:05 2006", 1136171045000000000],
        ["January 2, 2006", "March 10, 2024", 1710028800000000000],
        ["January 2, 2006", "december 31, 2023", 1703980800000000000],
        ["January 2, 2006", "Feb 1, 2024", nil],
        ["02 Jan 2006", "10 Mar 2024", 1710028800000000000],
        ["02 Jan 2006", "10 mar 2024", 1710028800000000000],
        ["02 Jan 2006", "1 Mar 2024", nil],
        ["2006-002", "2024-070", 1710028800000000000],
        ["2006-002", "2024-001", 1704067200000000000],
        ["2006-002", "2024-366", 1735603200000000000],
        ["2006-002", "2024-367", nil],
        ["2006-002", "2023-366", nil],
        ["15:04:05", "12:30:45", nil],
        ["3:04 PM", "11:30 PM", nil],
        ["3:04 PM", "12:30 AM", nil],
        ["3:04 PM", "12:30 PM", nil],
        ["3:04 PM", "1:05 AM", nil],
        ["03:04:05 PM", "11:30:45 PM", nil],
        ["03:04:05 PM", "12:30:45 AM", nil],
        ["03:04:05 PM", "12:30:45 PM", nil],
        ["03:04:05 PM", "13:30:45 PM", nil],
        ["2006-01-02T15:04:05Z07:00", "2024-03-10T12:30:45+05:30", 1710054045000000000],
        ["2006-01-02T15:04:05Z0700", "2024-03-10T12:30:45Z", 1710073845000000000],
        ["2006-01-02T15:04:05Z0700", "2024-03-10T12:30:45+0530", 1710054045000000000],
        ["2006-01-02T15:04:05Z07", "2024-03-10T12:30:45Z", 1710073845000000000],
        ["2006-01-02T15:04:05Z07", "2024-03-10T12:30:45+05", 1710055845000000000],
        ["2006-01-02 15:04:05 -07:00", "2024-03-10 12:30:45 -05:00", 1710091845000000000],
        ["2006-01-02 15:04:05 -07:00", "2024-03-10 12:30:45 +00:00", 1710073845000000000],
        ["2006-01-02 15:04:05 -0700", "2024-03-10 12:30:45 -0500", 1710091845000000000],
        ["2006-01-02 15:04:05 -07", "2024-03-10 12:30:45 -05", 1710091845000000000],
        ["2006-01-02 15:04:05 MST", "2024-03-10 12:30:45 MST", 1710073845000000000],
        ["2006-01-02 15:04:05 MST", "2024-03-10 12:30:45 UTC", 1710073845000000000],
        ["2006-01-02 15:04:05 MST", "2024-03-10 12:30:45 GMT", 1710073845000000000],
        ["2006-01-02 15:04:05 MST", "2024-03-10 12:30:45 PST", 1710073845000000000],
        ["2006-01-02 15:04:05 MST", "2024-03-10 12:30:45 ABC", 1710073845000000000],
        ["15:04:05.000 2006-01-02", "12:30:45.500 2024-03-10", 1710073845500000000],
        ["15:04:05.000 2006-01-02", "12:30:45.5 2024-03-10", nil],
        ["15:04:05.000 2006-01-02", "12:30:45.123 2024-03-10", 1710073845123000000],
        ["15:04:05.999 2006-01-02", "12:30:45.5 2024-03-10", 1710073845500000000],
        ["15:04:05.999 2006-01-02", "12:30:45 2024-03-10", 1710073845000000000],
        ["15:04:05.999 2006-01-02", "12:30:45.123456 2024-03-10", 1710073845123456000],
        ["15:04:05,000 2006-01-02", "12:30:45,500 2024-03-10", 1710073845500000000],
        ["2006-01-02T15:04:05Z07:00", "2024-03-10t12:30:45z", nil],
        ["2006-01-02 15:04:05", "2024-03-10 12:30", nil],
        ["2006-01-02", "2024-03-10extra", nil],
        ["2006-01-02", "not-a-date", nil]
    ].each do |layout, val, expected|
      it "parses #{layout.inspect} / #{val.inspect}" do
        expect(parse_ns(layout, val)).to eq(expected.nil? ? :undef : expected)
      end
    end

    # Edge cases surfaced by the adversarial review panel (each was a one-sided divergence from
    # Go's time.Parse), verified against `TZ=UTC opa eval` 1.17.
    [
      # A trailing layout space matches an exhausted value (Go's skip only errors on a non-empty
      # non-space value).
      ["2006-01-02 ", "2024-03-04", 1_709_510_400_000_000_000],
      # A bare second token absorbs a trailing value fraction (period or comma) when the layout
      # has no fraction token, truncating to nanoseconds (Go's stdSecond special case).
      ["2006-01-02 15:04:05", "2024-03-10 10:20:30.5", 1_710_066_030_500_000_000],
      ["2006-01-02 15:04:05", "2024-03-10 10:20:30,5", 1_710_066_030_500_000_000],
      ["2006-01-02 15:04:05", "2024-03-10 10:20:30.123456789999", 1_710_066_030_123_456_789],
      # A signed value after a named-zone token is consumed via parseSignedOffset (length only,
      # offset stays 0); an hour > 23 leaves leftover digits → undefined.
      ["2006-01-02 15:04:05 MST", "2024-03-10 12:30:45 +05", 1_710_073_845_000_000_000],
      ["2006-01-02 15:04:05 MST", "2024-03-10 12:30:45 +0530", nil],
      # A bare GMT sign with no following digit is not consumed → leftover "+" → undefined.
      ["2006-01-02 15:04:05 MST", "2024-03-10 12:30:45 GMT+", nil],
      # Zone offsets are range-checked per field: hour ≤ 24, minute/second ≤ 60.
      ["2006-01-02T15:04:05Z07:00", "2024-03-10T12:30:45+24:00", 1_709_987_445_000_000_000],
      ["2006-01-02T15:04:05Z07:00", "2024-03-10T12:30:45+25:00", nil],
      ["2006-01-02T15:04:05Z07:00", "2024-03-10T12:30:45+12:61", nil],
      # An offset of exactly -1 second collides with Go's "no zone" sentinel and is not applied
      # (kept naive); a -2s offset and a +1s offset apply normally — the boundary is exactly -1.
      ["2006-01-02T15:04:05-07:00:00", "2024-03-04T10:20:30-00:00:01", 1_709_547_630_000_000_000],
      ["2006-01-02T15:04:05-07:00:00", "2024-03-04T10:20:30-00:00:02", 1_709_547_632_000_000_000],
      ["2006-01-02T15:04:05-07:00:00", "2024-03-04T10:20:30+00:00:01", 1_709_547_629_000_000_000]
    ].each do |layout, val, expected|
      it "parses #{layout.inspect} / #{val.inspect} (panel regression)" do
        expect(parse_ns(layout, val)).to eq(expected.nil? ? :undef : expected)
      end
    end

    it "is undefined for an empty layout against any non-empty value" do
      expect(parse_ns("", "")).to eq(:undef) # year 0 -> out of int64-ns range
      expect(parse_ns("", "x")).to eq(:undef) # leftover text
    end

    it "is undefined for a non-string layout or value (runtime types)" do
      expect(registry.call("time.parse_ns", [42, "2024-03-10"]))
        .to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("time.parse_ns", ["2006-01-02", 42]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined (not a crash) for an invalid-encoding layout or value" do
      bad = +"Janu\xFFry"
      bad.force_encoding("UTF-8")
      expect(bad.valid_encoding?).to be(false)
      expect(parse_ns("January 2 2006", bad)).to eq(:undef)
      expect(parse_ns(bad, "March 2 2024")).to eq(:undef)
    end

    it "is undefined (not a crash) for a valid but ASCII-incompatible encoding (UTF-16)" do
      utf16 = "March 2 2024".encode("UTF-16LE")
      expect(utf16.valid_encoding?).to be(true) # the prior guard missed this; the crash is real
      expect(parse_ns("January 2 2006", utf16)).to eq(:undef)
      expect(parse_ns("2006".encode("UTF-16LE"), "2024")).to eq(:undef)
    end

    it "is undefined (not a crash) for a binary (ASCII-8BIT) string with high bytes" do
      # ASCII-8BIT is ascii_compatible? and always valid_encoding?, so it slipped past the
      # encoding guard and then broke the UTF-8 transcode downstream (in TZInfo / the regex).
      binary = (+"Mar\xFFch").force_encoding("ASCII-8BIT")
      expect(binary.valid_encoding?).to be(true)
      expect(parse_ns("January 2 2006", binary)).to eq(:undef)
      # also via a tz-consuming sibling that routes the string through TZInfo
      tz = (+"UTC\xFF").force_encoding("ASCII-8BIT")
      operand = Ruby::Rego::ArrayValue.new([Ruby::Rego::NumberValue.new(0), Ruby::Rego::StringValue.new(tz)])
      expect(registry.call("time.date", [operand])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end
# rubocop:enable Metrics/BlockLength
