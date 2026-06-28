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

    it "fails fast when the integer multiplier is outside OPA's uint64 SetUint64 range" do
      # OPA multiplies by m.SetUint64(unit): the multiplier is an unsigned 64-bit value, and EVERY uint64
      # is exact at precision 64 (so CONTEXT.Num never rounds it). A value outside [0, 2**64-1] would be
      # rounded (or is nonsensical as a unit multiplier), so it raises rather than return a silently-wrong
      # product. All OPA unit multipliers are <= 2**60, so this never fires in practice — it guards a
      # future/incorrect caller. (uint64 is the right contract, not bit_length: 2**64 has bit_length 65
      # yet is exactly representable, so a bit_length test would mischaracterize the boundary.)
      uint64_max = (2**64) - 1
      expect(described_class.prec64_multiply_truncate(Rational(1, 2), uint64_max)).to be_a(Integer)
      expect(described_class.prec64_multiply_truncate(Rational(1, 2), 2**60)).to be_a(Integer)
      expect { described_class.prec64_multiply_truncate(Rational(1, 2), uint64_max + 1) }
        .to raise_error(ArgumentError, /uint64/)
      # A negative multiplier is outside the unsigned range — bit_length would have wrongly accepted it.
      expect { described_class.prec64_multiply_truncate(Rational(1, 2), -1000) }
        .to raise_error(ArgumentError, /uint64/)
    end
  end

  describe ".product (OPA prec-64 big.Float fold)" do
    it "returns the multiplicative identity 1 for an empty fold" do
      expect(described_class.product([])).to eql(1)
    end

    it "folds integers through the prec-64 big.Float (no exact integer fast-path, unlike sum)" do
      expect(described_class.product([2, 3, 4])).to eq(24)
      # 2**96 exceeds prec-64, so the all-integer product is the big.Float-rounded value rendered
      # shortest — NOT the exact 79228162514264337593543950336. This is the defining product property.
      expect(described_class.product([2**32, 2**32, 2**32]).to_s).to eq("79228162514264337594000000000")
    end

    it "matches OPA's prec-64 fractional product byte-for-byte" do
      expect(described_class.product([0.1, 0.2, 0.3]).to_s).to eq("0.006000000000000000001")
    end

    it "collapses an integer-valued result back to a Ruby Integer" do
      expect(described_class.product([1.5, 2.0])).to eql(3)
    end

    it "raises RangeError when the final result magnitude exceeds the cap (DoS gate)" do
      huge = described_class.literal("1e20000")
      expect { described_class.product([huge, huge]) }.to raise_error(RangeError, /magnitude/)
    end

    it "raises RangeError for a tiny over-cap result too (the cap is on |log10|, both directions)" do
      # Two in-cap tiny factors multiply to 1e-60000, whose #exact would expand to a ~60000-digit
      # denominator Rational. The cap must be symmetric (mirroring the literal cap's .abs), else this
      # over-cap Number escapes the gate and amplifies on first comparison/sort/set-insert.
      tiny = described_class.literal("1e-30000")
      expect { described_class.product([tiny, tiny]) }.to raise_error(RangeError, /magnitude/)
    end

    it "raises RangeError when an intermediate overflows the engine exponent range (DoS gate)" do
      huge = described_class.literal("1e1000000")
      expect { described_class.product(Array.new(400) { huge }) }.to raise_error(RangeError, /overflow/)
    end
  end

  describe ".sum (OPA integer fast-path + prec-64 big.Float fold)" do
    def num(text) = described_class.literal(text)

    it "returns the additive identity 0 for an empty fold" do
      expect(described_class.sum([])).to eql(0)
    end

    it "sums plain integers within int64 exactly (the integer fast-path)" do
      expect(described_class.sum([100, 1])).to eql(101)
      expect(described_class.sum([1, 2, 3])).to eql(6)
      expect(described_class.sum([5])).to eql(5)
    end

    it "folds an exponent-form (Number) operand through the prec-64 big.Float, not exact integers" do
      # sum([1e20, 7]): 1e20 is a Number (not a plain int64), so OPA rounds the whole fold to prec-64
      # -> 100000000000000000010, NOT the exact 100000000000000000007 a naive Integer sum would give.
      expect(described_class.sum([num("1e20"), 7]).to_s).to eq("100000000000000000010")
    end

    it "folds a >int64 plain integer through the big.Float too (OPA's ParseInt rejects it)" do
      expect(described_class.sum([10**20, 7]).to_s).to eq("100000000000000000010")
    end

    it "matches OPA's catastrophic-cancellation result (the whole fold stays in big.Float)" do
      # 1e308 + 1 rounds back to 1e308, so the small terms vanish: OPA gives 2, not 3.
      expect(described_class.sum([num("1e308"), 1, num("-1e308"), 2])).to eql(2)
    end

    it "matches OPA's prec-64 fractional sum byte-for-byte" do
      expect(described_class.sum([num("0.1"), num("0.2"), num("0.3")]).to_s).to eq("0.6")
      expect(described_class.sum([num("2.5"), 1]).to_s).to eq("3.5")
    end

    it "collapses an integer-valued big.Float result back to a Ruby Integer" do
      expect(described_class.sum([num("0.5"), num("-0.5")])).to eql(0)
      expect(described_class.sum([num("1.5"), num("1.5")])).to eql(3)
    end

    it "renders a huge integer-valued big.Float sum shortest, like OPA's FloatToNumber" do
      expect(described_class.sum([num("1e308"), num("1e308")])).to eql(2 * (10**308))
    end

    # The one deliberate divergence from OPA: OPA's integer fast-path accumulates in a Go int64 and
    # SILENTLY WRAPS on overflow (sum([9e18, 9e18]) -> -446744073709551616). Replicating a silent
    # integer-overflow wrap in Ruby would turn a sum of positive quotas into a negative number — an
    # authorization hazard. Per the project's "implement correctly, document the divergence" precedent
    # for upstream bugs, the fast-path uses arbitrary-precision Ruby Integer and returns the true sum.
    it "returns the mathematically correct sum on int64 overflow (NOT OPA's silent wrap)" do
      expect(described_class.sum([9_000_000_000_000_000_000, 9_000_000_000_000_000_000]))
        .to eql(18_000_000_000_000_000_000)
      expect(described_class.sum([9_223_372_036_854_775_807, 1])).to eql(9_223_372_036_854_775_808)
      expect(described_class.sum([-9_223_372_036_854_775_808, -1])).to eql(-9_223_372_036_854_775_809)
    end

    it "raises RangeError when an element overflows the engine exponent range (totality, no crash)" do
      # A single element past ENGINE_EMAX (reachable via the library `input:` API or uncapped integer `*`)
      # trips the big.Float Add overflow trap. Like product's intermediate trap, it must surface as a
      # RangeError the builtin layer maps to undefined — NOT an uncaught Flt::Num::Exception that aborts
      # the policy. Built with a bit-shift so the ~128 MiB element allocates without a slow base-10 power.
      over_emax = 1 << (described_class::ENGINE_EMAX + 1)
      expect { described_class.sum([over_emax]) }.to raise_error(RangeError, /overflow/)
    end

    it "returns valid large sums far above the literal cap (sum has NO magnitude cap, unlike product)" do
      # Additive growth keeps sum well below ENGINE_EMAX, so a sum whose magnitude exceeds the literal cap
      # (1e30102) is returned, matching OPA — the engine-overflow rescue must NOT become a product-style cap.
      big = described_class.literal("1e60000")
      expect(described_class.sum([big, big]).to_s).to eq("2#{"0" * 60_000}")
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

  describe ".finite_real?" do
    it "accepts every orderable, foldable Numeric: Integer, Rational, ANY Number, and finite Float" do
      expect(described_class.finite_real?(5)).to be(true)
      expect(described_class.finite_real?(described_class.literal("1.5"))).to be(true)
      expect(described_class.finite_real?(Rational(1, 2))).to be(true)
      expect(described_class.finite_real?(1.5)).to be(true)
      # Magnitude is NOT this gate's concern — it answers only "can this be ordered and folded without
      # crashing". An over-cap Number is accepted here; its compact-exponent #exact amplification is a
      # gem-wide Value/Number boundary gap (host-only-reachable — untrusted decoders cap before a Number
      # is built), deferred to its own PR rather than half-closed at this gate. The check is O(1): no
      # materialization, so this assertion stays fast even on a billion-digit-magnitude Number.
      expect(described_class.finite_real?(described_class.literal("1e1000000000"))).to be(true)
    end

    it "rejects Complex (not real, not order-comparable, not big.Float-convertible)" do
      expect(described_class.finite_real?(Complex(1, 2))).to be(false)
    end

    it "rejects a non-finite Float" do
      expect(described_class.finite_real?(Float::INFINITY)).to be(false)
      expect(described_class.finite_real?(Float::NAN)).to be(false)
    end

    it "rejects BigDecimal even when finite (rational_of has no BigDecimal branch: unorderable vs Number)" do
      expect(described_class.finite_real?(BigDecimal("1.5"))).to be(false)
      expect(described_class.finite_real?(BigDecimal("1e10000000"))).to be(false)
      expect(described_class.finite_real?(BigDecimal("Infinity"))).to be(false)
      expect(described_class.finite_real?(BigDecimal("NaN"))).to be(false)
    end
  end
end

# rubocop:enable Metrics/BlockLength
