# frozen_string_literal: true

require "spec_helper"

# rubocop:disable Metrics/BlockLength

# Ruby::Rego::Number is the arbitrary-precision, OPA-faithful number type. All expected values were
# verified byte-for-byte against `opa eval` 1.17.
RSpec.describe Ruby::Rego::Number do
  describe ".literal" do
    it "preserves the source text verbatim (json.Number model)" do
      expect(described_class.literal("1.50").to_s).to eq("1.50")
      expect(described_class.literal("0.30").to_s).to eq("0.30")
      expect(described_class.literal("1e999").to_s).to eq("1e999")
      expect(described_class.literal("6.02e23").to_s).to eq("6.02e23")
    end

    it "exposes the exact value, collapsing an integer-valued literal to an Integer" do
      expect(described_class.literal("1.50").exact).to eq(Rational(3, 2))
      expect(described_class.literal("1.0").exact).to eq(1)
      expect(described_class.literal("1.0").exact).to be_a(Integer)
      expect(described_class.literal("0.1").exact).to eq(Rational(1, 10))
    end

    it "serializes to a raw JSON number token" do
      expect(described_class.literal("1.50").to_json).to eq("1.50")
      expect(JSON.generate([described_class.literal("1.50"), described_class.literal("1e999")]))
        .to eq("[1.50,1e999]")
    end
  end

  describe "arithmetic (big.Float at precision 64, round-half-even)" do
    def num(text) = described_class.literal(text)

    it "matches OPA on the classic divergent cases" do
      expect((num("0.1") + num("0.2")).to_s).to eq("0.3")
      expect((num("0.1") * num("0.1")).to_s).to eq("0.010000000000000000001")
      expect(described_class.div(1, 3).to_s).to eq("0.33333333333333333334")
      expect(described_class.div(2, 3).to_s).to eq("0.6666666666666666667")
    end

    it "collapses an integer-valued result back to a Ruby Integer" do
      expect(num("1.0") + num("1.0")).to eq(2)
      expect(num("1.0") + num("1.0")).to be_a(Integer)
      expect(num("2.5") * 4).to eq(10)
      expect(described_class.div(4, 2)).to be_a(Integer)
    end

    it "never overflows to a non-finite value (the serializer DoS is closed)" do
      result = num("1e308") * num("1e308")
      expect(result).to be_a(Integer)
      expect(result.to_s).to start_with("9999999999999999999")
      expect(result.to_s).to end_with("0000")
      expect((num("1e-300") * num("1e-300")).to_s).to eq("9.9999999999999999994e-601")
    end

    it "coerces an Integer or Float left operand through the big.Float engine" do
      expect((2 + num("1.5")).to_s).to eq("3.5")
      expect((10 - num("3.5")).to_s).to eq("6.5")
      expect((1 - num("0.25")).to_s).to eq("0.75")
    end

    it "negates" do
      expect((-num("1.5")).to_s).to eq("-1.5")
      expect(-num("1.0")).to eq(-1)
    end

    it "raises TypeError on a non-numeric operand, like any Numeric" do
      # rubocop:disable Style/StringConcatenation -- exercising a non-numeric operand, not concatenating
      expect { num("1.5") + "x" }.to raise_error(TypeError)
      # rubocop:enable Style/StringConcatenation
    end
  end

  describe ".div (always big.Float)" do
    it "produces a fractional quotient where Ruby integer division would truncate" do
      expect(described_class.div(5, 2).to_s).to eq("2.5")
      expect(described_class.div(-5, 2).to_s).to eq("-2.5")
      expect(described_class.div(4, 2)).to eq(2)
    end
  end

  describe ".modulo (integer-only, Go truncated remainder)" do
    def num(text) = described_class.literal(text)

    it "is integer-valued only and otherwise nil (-> undefined)" do
      expect(described_class.modulo(5, 2)).to eq(1)
      expect(described_class.modulo(num("4.0"), 2)).to eq(0)
      expect(described_class.modulo(num("5.5"), 2)).to be_nil
      expect(described_class.modulo(5, num("2.5"))).to be_nil
    end

    it "takes the sign of the dividend (truncated, not floored)" do
      expect(described_class.modulo(-5, 3)).to eq(-2)
      expect(described_class.modulo(5, -3)).to eq(2)
    end
  end

  describe ".prec64_multiply_truncate (OPA units.parse_bytes big.Float path)" do
    it "multiplies in a prec-64 big.Float and truncates toward zero" do
      # Binary-exact operands are unaffected: 3/2 * 1000 = 1500 exactly.
      expect(described_class.prec64_multiply_truncate(Rational(3, 2), 1000)).to eq(1500)
      expect(described_class.prec64_multiply_truncate(Rational(0), 1000)).to eq(0)
      # An identity multiply (integer 1) still rounds the amount to the prec-64 float and truncates.
      expect(described_class.prec64_multiply_truncate(Rational(107, 10), 1)).to eq(10) # 10.7 -> 10
    end

    it "rounds via the prec-64 binary float, not exact rational (matching OPA byte-for-byte)" do
      # 0.001 has no exact binary form; rounded to prec 64 and * 10**6 it lands just under 1000,
      # so it truncates to 999 — NOT the exact-rational 1000. This is the defining divergence.
      expect(described_class.prec64_multiply_truncate(Rational(1, 1000), 10**6)).to eq(999)
      # A >19-significant-digit amount (numerator past 2**64) single-rounds (no double-rounding).
      expect(described_class.prec64_multiply_truncate(Rational("9999999999.99999999995"), 1)).to eq(10_000_000_000)
    end

    it "truncates a negative product toward zero (big.Float.Int), not floored" do
      expect(described_class.prec64_multiply_truncate(Rational(-1, 1000), 10**6)).to eq(-999)
    end

    it "fails fast when the integer multiplier is not exact at precision 64" do
      # A multiplier wider than 64 bits would be silently rounded by CONTEXT.Num, producing a wrong
      # result; the contract requires bit_length <= 64, so it raises instead (all OPA unit multipliers
      # are <= 2**60, so this never fires in practice — it guards a future/incorrect caller).
      expect { described_class.prec64_multiply_truncate(Rational(1, 2), (2**64) + 1) }
        .to raise_error(ArgumentError, /precision 64/)
      expect(described_class.prec64_multiply_truncate(Rational(1, 2), 2**60)).to be_a(Integer)
    end
  end

  describe "equality and ordering by exact value" do
    def num(text) = described_class.literal(text)

    it "compares numerically equal regardless of representation" do
      expect(num("1.50") == num("1.5")).to be(true)
      expect(num("1.0") == 1).to be(true)
      expect(num("0.30") == Rational(3, 10)).to be(true)
    end

    it "orders against any Numeric" do
      expect(num("1.5") < 2).to be(true)
      expect(num("2.5") > 2).to be(true)
      expect(3 > num("2.5")).to be(true) # rubocop:disable Style/YodaCondition -- Integer coercing a Number
      expect([num("3.3"), num("1.1"), num("2.2")].sort.map(&:to_s)).to eq(%w[1.1 2.2 3.3])
    end

    it "hashes consistently with eql? so a Set dedups equal Numbers" do
      expect(Set[num("1.50"), num("1.5")].size).to eq(1)
    end

    it "returns nil from <=> for a non-numeric, so comparison is undefined not a crash" do
      expect(num("1.5") <=> "x").to be_nil
    end
  end

  describe "magnitude limit (matches OPA's \"number too big\", bounds rational materialization)" do
    it "accepts a literal at OPA's boundary and rejects beyond it" do
      expect(described_class.magnitude_within_limit?("1e30102")).to be(true)
      expect(described_class.magnitude_within_limit?("1e30103")).to be(false)
      expect(described_class.magnitude_within_limit?("1e-30102")).to be(true)
      expect(described_class.magnitude_within_limit?("0.0")).to be(true)
    end

    it "rejects an unbounded-exponent literal cheaply (no 10**exp materialization)" do
      # The amplification DoS: 12 source bytes must not allocate a gigabyte rational.
      expect(described_class.magnitude_within_limit?("1e999999999")).to be(false)
      expect(described_class.magnitude_within_limit?("1e-999999999")).to be(false)
    end

    it "routes on the caller-supplied fractional flag (callers must compute it correctly)" do
      # The flag is a precomputed dispatch hint, not validated input: passing fractional:false for a
      # genuinely fractional token routes it down the integer digit-count path and bypasses the BigDecimal
      # magnitude check. Both real callers derive the flag exactly as the default does, so this misuse is
      # unreachable in production; pinned here to document the caller contract the optimization relies on.
      expect(described_class.magnitude_within_limit?("1e99999", fractional: false)).to be(true)  # bypass
      expect(described_class.magnitude_within_limit?("1e99999", fractional: true)).to be(false)  # checked
      expect(described_class.magnitude_within_limit?("1e99999")).to be(false) # default derives it correctly
    end

    it "checks a plain integer's magnitude by digit count, without building a BigDecimal" do
      # The single gate both the lexer and the JSON decoder share. A plain integer (no leading zeros per
      # the NUMBER grammar) has magnitude = significant-digit-count - 1, so the boundary is 30103 digits;
      # a leading sign does not count. Equivalent to the BigDecimal exponent path (verified), but cheaper.
      expect(described_class.magnitude_within_limit?("9" * 30_103)).to be(true)   # 1e30102 magnitude
      expect(described_class.magnitude_within_limit?("9" * 30_104)).to be(false)  # 1e30103 magnitude
      expect(described_class.magnitude_within_limit?("-#{"9" * 30_103}")).to be(true) # sign not counted
      expect(described_class.magnitude_within_limit?("-#{"9" * 30_104}")).to be(false)
      expect(described_class.magnitude_within_limit?("0")).to be(true)
      expect(described_class.magnitude_within_limit?("-0")).to be(true)
    end

    it "rejects an exponent so large BigDecimal saturates (no spurious accept), both directions" do
      # ~19+ exponent digits make BigDecimal(text) saturate WITHOUT raising: a huge positive exponent
      # to Infinity, a huge negative one underflowing to 0 (both exponent 0). An un-guarded check would
      # accept them and then crash (FloatDomainError) or silently mis-evaluate the tiny value as 0.
      expect(described_class.magnitude_within_limit?("1e9999999999999999999")).to be(false)
      expect(described_class.magnitude_within_limit?("1e-9999999999999999999")).to be(false)
    end

    it "still accepts a genuine zero carrying a huge exponent" do
      expect(described_class.magnitude_within_limit?("0e-9999999999999999999")).to be(true)
      expect(described_class.magnitude_within_limit?("0.0e1000000000")).to be(true)
    end

    it "rejects an over-large literal at parse, like OPA, rather than evaluating it" do
      %w[1e999999999 1e9999999999999999999 1e-9999999999999999999].each do |literal|
        expect do
          Ruby::Rego.evaluate("package t\nx = #{literal} > 1", query: "data.t.x")
        end.to raise_error(Ruby::Rego::LexerError)
      end
    end
  end

  describe ".negate_literal preserves a negative literal's text" do
    it "toggles the sign of the text instead of recomputing the value" do
      expect(described_class.negate_literal(described_class.literal("1.50")).to_s).to eq("-1.50")
      expect(described_class.negate_literal(described_class.literal("0.0")).to_s).to eq("-0.0")
      expect(described_class.negate_literal(described_class.literal("-1.50")).to_s).to eq("1.50")
      expect(described_class.negate_literal(5)).to eq(-5)
    end
  end

  describe "Numeric conversions" do
    def num(text) = described_class.literal(text)

    it "truncates to_i toward zero and exposes an exact to_r" do
      expect(num("1.9").to_i).to eq(1)
      expect(num("-1.9").to_i).to eq(-1)
      expect(num("1.50").to_r).to eq(Rational(3, 2))
    end

    it "reports integer_valued?, zero?, negative?" do
      expect(num("1.0").integer_valued?).to be(true)
      expect(num("1.5").integer_valued?).to be(false)
      expect(num("0.0").zero?).to be(true)
      expect(num("-1.5").negative?).to be(true)
    end
  end
end

# rubocop:enable Metrics/BlockLength
