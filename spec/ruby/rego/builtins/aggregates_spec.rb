# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe "aggregate builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  it "counts arrays, objects, sets, and strings" do
    expect(registry.call("count", [[1, 2, 3]]).to_ruby).to eq(3)
    expect(registry.call("count", [{ "a" => 1, "b" => 2 }]).to_ruby).to eq(2)
    expect(registry.call("count", [Set.new(%w[a b])]).to_ruby).to eq(2)
    expect(registry.call("count", ["rego"]).to_ruby).to eq(4)
  end

  it "sums numeric arrays" do
    expect(registry.call("sum", [[1, 2, 3]]).to_ruby).to eq(6)
  end

  it "raises for non-numeric sum elements" do
    result = registry.call("sum", [[1, "x"]])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "computes max and min for numeric arrays" do
    expect(registry.call("max", [[2, 5, 3]]).to_ruby).to eq(5)
    expect(registry.call("min", [[2, 5, 3]]).to_ruby).to eq(2)
  end

  it "raises for empty max and min" do
    max_result = registry.call("max", [[]])
    min_result = registry.call("min", [[]])

    expect(max_result).to be_a(Ruby::Rego::UndefinedValue)
    expect(min_result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "computes sum, max, and min over sets (OPA accepts arrays and sets alike)" do
    expect(registry.call("sum", [Set.new([1, 2, 3])]).to_ruby).to eq(6)
    expect(registry.call("max", [Set.new([2, 5, 3])]).to_ruby).to eq(5)
    expect(registry.call("min", [Set.new([2, 5, 3])]).to_ruby).to eq(2)
  end

  it "sorts a mixed Integer/Number set without a Comparable crash (the coerce-on-sort path)" do
    half = Ruby::Rego::Number.literal("1.5")
    expect(registry.call("sum", [Set.new([1, half])]).to_ruby.to_s).to eq("2.5")
    expect(registry.call("max", [Set.new([1, half])]).to_ruby.to_s).to eq("1.5")
    expect(registry.call("product", [Set.new([2, half])]).to_ruby.to_s).to eq("3")
  end

  it "is undefined for max/min over an empty set (matching the empty-array behaviour)" do
    expect(registry.call("max", [Set.new([])])).to be_a(Ruby::Rego::UndefinedValue)
    expect(registry.call("min", [Set.new([])])).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "is undefined for sum/max/min over a set with a non-number element" do
    expect(registry.call("sum", [Set.new([1, "x"])])).to be_a(Ruby::Rego::UndefinedValue)
    expect(registry.call("max", [Set.new([1, "x"])])).to be_a(Ruby::Rego::UndefinedValue)
    expect(registry.call("min", [Set.new([1, "x"])])).to be_a(Ruby::Rego::UndefinedValue)
  end

  describe "product" do
    it "returns 1 for an empty collection (multiplicative identity, matching OPA)" do
      expect(registry.call("product", [[]]).to_ruby).to eql(1)
    end

    it "multiplies array elements" do
      expect(registry.call("product", [[7]]).to_ruby).to eq(7)
      expect(registry.call("product", [[2, 3, 4]]).to_ruby).to eq(24)
      expect(registry.call("product", [[-2, 3]]).to_ruby).to eq(-6)
      expect(registry.call("product", [[2, 0, 5]]).to_ruby).to eq(0)
    end

    it "collapses an integer-valued float product to an Integer (OPA FloatToNumber)" do
      expect(registry.call("product", [[1.5, 2.0]]).to_ruby).to eql(3)
    end

    it "matches OPA's prec-64 big.Float fractional product byte-for-byte" do
      expect(registry.call("product", [[0.1, 0.2, 0.3]]).to_ruby.to_s).to eq("0.006000000000000000001")
    end

    it "accepts sets, iterating in OPA's sorted order" do
      expect(registry.call("product", [Set.new([2, 3, 4])]).to_ruby).to eq(24)
      expect(registry.call("product", [Set.new([1.5, 2])]).to_ruby).to eql(3)
    end

    it "is undefined for a non-collection, a non-number element, or an object argument" do
      expect(registry.call("product", ["foo"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("product", [[1, "a"]])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("product", [[1, nil]])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("product", [Set.new([1, "a"])])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("product", [{ "k" => 1 }])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined when the result exceeds the magnitude cap (DoS gate, no giant materialization)" do
      # product is the only numeric builtin with an unbounded fold, so its result magnitude can grow
      # without bound. A result past MAX_MAGNITUDE_EXPONENT maps to undefined BEFORE it materializes as a
      # multi-megabyte Integer string. Two in-cap literals whose product (1e40000) clears the cap, so the
      # gate fires with no intermediate overflow. Stricter than OPA (which returns 1e40000) — documented
      # DoS hardening for the one UNBOUNDED fold; single ops (`*`/`/`) stay uncapped to match OPA, so this
      # is not a global magnitude invariant.
      huge = Ruby::Rego::Number.literal("1e20000")
      expect(registry.call("product", [[huge, huge]])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a tiny over-cap result too (symmetric cap, both directions, no amplification)" do
      # The magnitude cap is on |log10|, not just the upper side. product of two in-cap tiny factors
      # (1e-30000 each) yields 1e-60000, whose #exact would expand to a ~60000-digit-denominator Rational
      # on the first comparison/sort/set-insert — an amplification DoS reachable from untrusted input
      # (each factor clears the per-element decoder cap). It must map to undefined before that materializes.
      tiny = Ruby::Rego::Number.literal("1e-30000")
      expect(registry.call("product", [[tiny, tiny]])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined when an intermediate overflows the engine exponent range (totality, no crash)" do
      # Past ENGINE_EMAX a running product trips the big.Float overflow trap mid-fold (before the final
      # magnitude cap is even reached), mapping to undefined like sum's non-finite overflow instead of
      # raising and aborting the policy. Reachable only by multiplying enormous magnitudes.
      huge = Ruby::Rego::Number.literal("1e1000000")
      overflowing = Array.new(400) { huge }
      expect { registry.call("product", [overflowing]) }.not_to raise_error
      expect(registry.call("product", [overflowing])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "does not swallow a non-magnitude RangeError (the rescue is narrowed to fail fast)" do
      # bounded_fold maps ONLY Number's MagnitudeError (a RangeError subclass) to undefined. An unexpected
      # plain RangeError — e.g. from a future Number internal — must propagate and abort the policy, not be
      # mislabeled "magnitude overflow -> undefined" and mask a bug. (Library code fails fast.)
      allow(Ruby::Rego::Number).to receive(:product).and_raise(RangeError, "unexpected from internals")
      expect { registry.call("product", [[1, 2]]) }.to raise_error(RangeError, "unexpected from internals")
    end

    # A large-magnitude integer-valued product exercises the number model's pre-existing shortest-form
    # limitation: flt's shortest decimal can differ from Go strconv's by one digit at the extreme, so
    # the gem renders `[2**32]*3` (= the big.Float of 2**96) as ...594 where OPA emits ...590. This is
    # NOT product-specific — it is identical to the shipped `div` path and the number model's own
    # rendering, i.e. product faithfully inherits the engine, introducing no new divergence class. The
    # gem value is pinned here to track the gap (it is consistency, not correctness); fixing the
    # flt-vs-Go shortest-form gap is a tracked number-sweep item that will move all of these together.
    it "inherits the number model's large-magnitude shortest-form gap (consistent with div, not OPA)" do
      product = registry.call("product", [[2**32, 2**32, 2**32]]).to_ruby.to_s
      via_number_model = Ruby::Rego::Number.from_binnum(Ruby::Rego::Number.rational_to_binnum(2**96)).to_s

      expect(product).to eq(via_number_model)
      expect(product).to eq("79228162514264337594000000000") # OPA: ...590000000000 (tracked)
    end
  end

  describe "sum (OPA integer fast-path + prec-64 big.Float fold)" do
    def num(text) = Ruby::Rego::Number.literal(text)

    it "returns 0 for an empty collection (additive identity, matching OPA)" do
      expect(registry.call("sum", [[]]).to_ruby).to eql(0)
    end

    it "folds a non-int64 operand through the big.Float, matching OPA (fixes the exact-integer drift)" do
      # The defining fix: 1e20 is a Number, so the WHOLE fold rounds at prec-64 -> ...010, where the old
      # Ruby Array#sum resumed exact integer addition and produced ...007.
      expect(registry.call("sum", [[num("1e20"), 7]]).to_ruby.to_s).to eq("100000000000000000010")
      expect(registry.call("sum", [[10**20, 7]]).to_ruby.to_s).to eq("100000000000000000010")
    end

    it "matches OPA's catastrophic-cancellation result" do
      expect(registry.call("sum", [[num("1e308"), 1, num("-1e308"), 2]]).to_ruby).to eql(2)
    end

    it "matches OPA's prec-64 fractional sum byte-for-byte" do
      expect(registry.call("sum", [[num("0.1"), num("0.2"), num("0.3")]]).to_ruby.to_s).to eq("0.6")
    end

    it "deduplicates a set before folding (OPA set semantics)" do
      expect(registry.call("sum", [Set.new([num("5e18"), num("5e18")])]).to_ruby.to_s)
        .to eq("5000000000000000000")
    end

    # The deliberate, documented divergence: OPA's int64 fast-path silently wraps on overflow
    # (sum([9e18, 9e18]) -> -446744073709551616). The gem keeps arbitrary precision and returns the true
    # sum — a sum of positive quotas must never come back negative. See Number.sum.
    it "returns the correct sum on int64 overflow rather than OPA's silent wrap" do
      expect(registry.call("sum", [[9_000_000_000_000_000_000, 9_000_000_000_000_000_000]]).to_ruby)
        .to eql(18_000_000_000_000_000_000)
    end

    it "is undefined when an element overflows the engine exponent range (totality, no crash)" do
      # Unlike product, sum has no magnitude cap (additive growth), but it still needs the engine-overflow
      # backstop: a single element past ENGINE_EMAX (reachable via the Ruby `input:` API, which does not
      # magnitude-cap an Integer the way the JSON decoder does) trips the big.Float Add trap. It must map
      # to undefined, NOT abort the policy with an uncaught Flt::Num::Exception. Built via bit-shift so the
      # ~128 MiB element allocates without a slow base-10 power.
      over_emax = 1 << (Ruby::Rego::Number::ENGINE_EMAX + 1)
      expect { registry.call("sum", [[over_emax]]) }.not_to raise_error
      expect(registry.call("sum", [[over_emax]])).to be_a(Ruby::Rego::UndefinedValue)
    end

    # Sum inherits the number model's flt-vs-Go shortest-form tie-break gap (shared with the big.Float
    # paths div/product/fractional-*; integer * stays exact native bignum and is unaffected):
    # 2**64 + 2**64 = 2**65, which the gem renders as the exact 36893488147419103232 while OPA's shortest
    # round-tripping decimal at prec-64 is 36893488147419103230. Magnitude-correct, both round-trip to the
    # same prec-64 float. Pinned to track the gap (a number-sweep item that will move all of these together).
    it "inherits the number model's shortest-form gap (consistent with product, not OPA)" do
      sum = registry.call("sum", [[2**64, 2**64]]).to_ruby.to_s
      via_number_model = Ruby::Rego::Number.from_binnum(Ruby::Rego::Number.rational_to_binnum(2**65)).to_s

      expect(sum).to eq(via_number_model)
      expect(sum).to eq("36893488147419103232") # OPA: 36893488147419103230 (tracked)
    end
  end

  describe "totality against non-real / non-finite / unsupported Numeric input (Ruby input: API)" do
    # Value.from_ruby admits ANY Ruby Numeric into a NumberValue (its non-finite guard is ::Float-only),
    # so a host can pass a Complex, a non-finite Float, or a BigDecimal through the library `input:` API.
    # Those reach the aggregates as NumberValue-wrapped exotics and previously aborted the policy: the
    # array fold crashed converting them, and the SET path (added with set support) crashed in the
    # pre-fold `sort` for ALL four numeric aggregates (Complex/BigDecimal have no usable ordering against
    # a Number). They must map to undefined, never raise. The fix is a finite-real gate (Number.finite_real?
    # — exactly the Integer/Rational/Number/finite-Float domain Number#rational_of can order and fold) in
    # the shared extract_numeric_elements chokepoint, which runs before both the sort and the fold.
    #
    # NOT covered here (deferred): a compact over-cap Number is an amplifier (its #exact expands to a giant
    # Rational) that blows up at canonicalization — when it is put in a set/object, BEFORE any aggregate
    # gate runs — so it can't be closed at this layer, and the gate accepts it (magnitude is not a crash).
    # It is untrusted-reachable, but NOT via the decoders (to_number rejects, the json/yaml decoders cap or
    # fall back to a string) — via the uncapped `*`/`/` operators, which match OPA's value-returning
    # big.Float by design (`1e-30000 * 1e-30000` -> `1e-60000`, doubling per step in a squaring chain). It
    # is a pre-existing number-model gap (lazy #exact on a compact result), emin-bounded, NOT widened by
    # this change — product is now the one path that can no longer manufacture it — so it is a gem-wide
    # Value/Number boundary concern for its own PR (see PR notes). No test asserts it: exercising the
    # amplification would have to materialize it (slow/heavy), and asserting it returns undefined would
    # encode the unwanted blow-up as expected behavior.
    #
    # BigDecimal is rejected even when finite: rational_of can't order it against a Number (would crash a
    # mixed sort/compare). Admitting it needs a BigDecimal branch at the core arithmetic layer (a
    # pre-existing gem-wide gap — see PR notes), out of scope here.
    %w[sum product max min].each do |fn|
      [Complex(1, 2), BigDecimal("2.5"), BigDecimal("NaN"), Float::INFINITY].each do |bad|
        it "is undefined for a #{bad.class}(#{bad}) element in an array (#{fn})" do
          expect { registry.call(fn, [[bad, 1]]) }.not_to raise_error
          expect(registry.call(fn, [[bad, 1]])).to be_a(Ruby::Rego::UndefinedValue)
        end

        it "is undefined for a #{bad.class}(#{bad}) element in a set, before the sort (#{fn})" do
          expect { registry.call(fn, [Set.new([bad, 1])]) }.not_to raise_error
          expect(registry.call(fn, [Set.new([bad, 1])])).to be_a(Ruby::Rego::UndefinedValue)
        end
      end
    end

    it "still folds a Rational element (Number#rational_of orders/folds it; no amplification)" do
      expect(registry.call("sum", [[Rational(1, 2), 1]]).to_ruby.to_s).to eq("1.5")
      expect(registry.call("product", [[Rational(3, 2), 2]]).to_ruby.to_s).to eq("3")
      # max/min return the winning element as-is (no fold), so a set with a Rational must at least sort
      # and select without raising; the larger element (3/2) is returned.
      expect(registry.call("max", [Set.new([Rational(3, 2), 1])]).to_ruby).to eq(Rational(3, 2))
    end
  end

  it "evaluates all and any using Rego truthiness" do
    expect(registry.call("all", [[true, "x"]]).to_ruby).to be(true)
    expect(registry.call("all", [[true, nil]]).to_ruby).to be(false)
    expect(registry.call("any", [[nil, false, 1]]).to_ruby).to be(true)
    expect(registry.call("any", [[]]).to_ruby).to be(false)
  end

  it "allows repeated registration" do
    expect { Ruby::Rego::Builtins::Aggregates.register! }.not_to raise_error
    expect { Ruby::Rego::Builtins::Aggregates.register! }.not_to raise_error
  end
end

# rubocop:enable Metrics/BlockLength
