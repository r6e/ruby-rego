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
      # DoS hardening that holds the whole number model to a single magnitude invariant.
      huge = Ruby::Rego::Number.literal("1e20000")
      expect(registry.call("product", [[huge, huge]])).to be_a(Ruby::Rego::UndefinedValue)
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
