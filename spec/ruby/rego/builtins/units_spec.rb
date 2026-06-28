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
    it "parses plain numbers, returning integers and precision-preserving numbers" do
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
      # OPA's milli uses float64(0.001), so an exact multiple of 1000 is still a non-integer result,
      # rendered to 10 decimals ("1.0000000000"), not collapsed to the integer 1.
      expect(parse("1000m").to_ruby).to eq(1.0)
      expect(parse("1000m").to_ruby.to_s).to eq("1.0000000000")
      expect(parse("1000m").to_ruby).to be_a(Ruby::Rego::Number)
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
      expect(parse("10.123456789012m").to_ruby.to_s).to eq("0.0101234568")
    end

    it "formats a non-integer result as fixed 10-decimal text, like OPA's big.Rat.FloatString(10)" do
      # A non-integer result keeps exactly 10 decimal places (trailing zeros included), rounded
      # half-away-from-zero, as a precision-preserving Number rather than a lossy Ruby Float.
      expect(parse("0.0015K").to_ruby.to_s).to eq("1.5000000000")
      expect(parse("10.5").to_ruby.to_s).to eq("10.5000000000")
      expect(parse("-0.0015K").to_ruby.to_s).to eq("-1.5000000000")
      # Rounds half away from zero at the 10th decimal.
      expect(parse("0.00000000005").to_ruby.to_s).to eq("0.0000000001")
      # A result that rounds to zero is still rendered with 10 decimals (its unrounded value is
      # non-integer), NOT collapsed to the integer 0 — and a negative one keeps its sign, like
      # Go's big.Rat.FloatString (the sign comes from the numerator, not the rounded mantissa).
      expect(parse("0.00000000001").to_ruby.to_s).to eq("0.0000000000")
      expect(parse("-0.00000000001").to_ruby.to_s).to eq("-0.0000000000")
      # Rounding carries across the decimal point.
      expect(parse("0.99999999999").to_ruby.to_s).to eq("1.0000000000")
      expect(parse("0.0015K").to_ruby).to be_a(Ruby::Rego::Number)
    end

    it "returns an exact integer when the unrounded result is integer-valued" do
      expect(parse("10.5K").to_ruby).to eq(10_500)
      expect(parse("10.5K").to_ruby).to be_a(Integer)
      # "0.0" is an exact integer zero (denominator 1), so it stays the integer 0, not "0.0000000000".
      expect(parse("0.0").to_ruby).to eq(0)
      expect(parse("0.0").to_ruby).to be_a(Integer)
    end

    it "accepts scientific notation (both e/E, with optional exponent sign) and the exa suffix" do
      expect(parse("1e3K").to_ruby).to eq(1_000_000)
      expect(parse("1E3K").to_ruby).to eq(1_000_000)
      expect(parse("1e+3K").to_ruby).to eq(1_000_000)
      expect(parse("1.5e-3K").to_ruby).to eq(1.5)
      expect(parse("10e").to_ruby).to eq(10_000_000_000_000_000_000)
    end

    it "rejects a bare-dot amount with no mantissa digit, matching OPA's big.Rat" do
      # Ruby's Rational(".") is 0, but Go's big.Rat.SetString(".") fails, so OPA is undefined.
      # The gem previously returned 0 (fail-open); it now rejects these to undefined.
      expect(parse(".")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse("+.")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse("-.")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse(".K")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse(".e3")).to be_a(Ruby::Rego::UndefinedValue) # exponent digit, but no mantissa digit
    end

    it "accepts a trailing-dot amount followed by an exponent (D. eNN), matching OPA's big.Rat" do
      # Ruby's Rational("5.e3") raises, but Go's big.Rat.SetString accepts it as 5e3. The gem
      # previously returned undefined (too strict); it now matches OPA.
      expect(parse("5.e3").to_ruby).to eq(5000)
      expect(parse("-5.e3").to_ruby).to eq(-5000)
      expect(parse("+5.e3").to_ruby).to eq(5000)
      expect(parse("12.E3").to_ruby).to eq(12_000)
      expect(parse("5.e-3").to_ruby.to_s).to eq("0.0050000000")
      expect(parse("5.e3K").to_ruby).to eq(5_000_000)
      # A leading dot with a fractional digit, or a trailing dot without an exponent, already
      # matched OPA and still does.
      expect(parse(".5e3").to_ruby).to eq(500)
      expect(parse("5.").to_ruby).to eq(5)
    end

    it "rejects a dangling exponent (e/E with a sign but no digits), matching OPA's big.Rat" do
      # Ruby's Rational("1e+") is 1, but Go's big.Rat requires an exponent digit, so OPA is
      # undefined. The gem previously returned the mantissa value (fail-open); it now rejects these.
      expect(parse("1e+")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse("1e-")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse("1E+")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse("-1e+")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse(".1e+")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse("1e+K")).to be_a(Ruby::Rego::UndefinedValue)
      # A bare "e" with no following digit/sign is still the exa unit, not an exponent, matching OPA.
      expect(parse("1e").to_ruby).to eq(1_000_000_000_000_000_000)
    end

    it "is undefined for a non-ASCII or invalid-encoding operand (matching OPA, no crash)" do
      # A valid quantity is pure ASCII; OPA returns undefined for any non-ASCII operand. The gem
      # must not raise (an invalid-UTF-8 ArgumentError would escape the builtin as a DoS).
      expect(parse("10K€")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse("10K\xFF".dup.force_encoding("UTF-8"))).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse_bytes("10kb\xFF".dup.force_encoding("UTF-8"))).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for an operand longer than the DoS cap (OPA relies on Go's runtime)" do
      expect(parse("1#{"0" * 1_000_000}")).to be_a(Ruby::Rego::UndefinedValue)
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

    it "removes embedded double-quotes from the value, matching OPA" do
      expect(parse_bytes(%(1"0kb)).to_ruby).to eq(10_000)
    end

    it "is undefined for a bare b, spaces, unknown units, bad amounts, or non-strings" do
      expect(parse_bytes("10b")).to be_a(Ruby::Rego::UndefinedValue) # bare b is not a unit
      expect(parse_bytes(" 10kb")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse_bytes("abc")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse_bytes("")).to be_a(Ruby::Rego::UndefinedValue)
      expect(parse_bytes(42)).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "matches OPA's 64-bit big.Float arithmetic byte-for-byte" do
      # OPA's parse_bytes parses the amount to a prec-64 big.Float (SetString), multiplies by the
      # unit at that precision, then truncates the product toward zero (big.Float.Int). A fractional
      # amount whose binary approximation lands just under an integer therefore truncates down — it
      # is NOT exact-rational arithmetic. Verified vs `opa eval` 1.17.1.
      expect(parse_bytes("0.001mb").to_ruby).to eq(999) # was 1000 under exact rational
      expect(parse_bytes("0.001k").to_ruby).to eq(0)
      expect(parse_bytes("0.001gb").to_ruby).to eq(999_999)
      # big.Float.Int truncates toward zero, so a negative is NOT floored.
      expect(parse_bytes("-0.001mb").to_ruby).to eq(-999)
      expect(parse_bytes("0kb").to_ruby).to eq(0)
      # A >19-significant-digit amount (numerator past 2**64) still matches: flt keeps the integer
      # coefficients exact, so the divide single-rounds like big.Float.SetString (no double-rounding).
      expect(parse_bytes("9999999999.99999999995").to_ruby).to eq(10_000_000_000)
      expect(parse_bytes("999999999999999999.5kb").to_ruby).to eq(999_999_999_999_999_999_488)
      # A large-exponent amount differs from the exact integer in nearly every digit.
      huge = "9999999999999999999669353532207342619498699019828496079271" \
             "391541752018669482644324418977840117055488"
      expect(parse_bytes("1e100").to_ruby).to eq(huge.to_i)
    end

    it "keeps the worst-case product's binary exponent below the engine's emax (DoS-safety invariant)" do
      # parse_bytes routes through a big.Float whose to_i raises (a non-BuiltinArgumentError that would
      # escape as a DoS) only on an infinity. The MAX_SOURCE / MAX_EXPONENT_DIGITS caps keep the largest
      # producible product far below CONTEXT.emax, so to_i is always finite. This pins that proof: if a
      # future cap change broke the margin, this fails loudly. (Verified ~162x margin vs `opa eval`.)
      units = Ruby::Rego::Builtins::Units
      worst_decimal_exp = units::MAX_SOURCE + (10**units::MAX_EXPONENT_DIGITS) # mantissa digits + 10**exp
      worst_binary_exp = (worst_decimal_exp * Math.log2(10)) + 60 # +60 binary orders for the 2**60 max unit
      # Compared against the engine's exponent ceiling via its named constant (the same value CONTEXT is
      # built with), so the proof has a single source of truth and stays independent of CONTEXT's visibility.
      expect(worst_binary_exp).to be < Ruby::Rego::Number::ENGINE_EMAX
    end

    it "still computes binary-exact amounts identically (big.Float == rational there)" do
      # An amount and product representable exactly in binary are unaffected by the big.Float route.
      expect(parse_bytes("1.5kib").to_ruby).to eq(1536)
      expect(parse_bytes("10.7").to_ruby).to eq(10)
      expect(parse_bytes("-5kb").to_ruby).to eq(-5000)
      expect(parse_bytes("1TiB").to_ruby).to eq(1024**4)
    end
  end
end
# rubocop:enable Metrics/BlockLength
