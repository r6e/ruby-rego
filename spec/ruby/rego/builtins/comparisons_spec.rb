# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe "comparison builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  it "compares values with deep equality" do
    expect(registry.call("equal", [[1, 2], [1, 2]]).to_ruby).to be(true)
    expect(registry.call("equal", [Set.new([1, 2]), Set.new([2, 1])]).to_ruby).to be(true)
    expect(registry.call("equal", [{ "a" => [1] }, { "a" => [1] }]).to_ruby).to be(true)
  end

  it "converts strings to numbers" do
    expect(registry.call("to_number", ["42"]).to_ruby).to eq(42)
    expect(registry.call("to_number", ["3.5"]).to_ruby).to eq(3.5)
  end

  it "raises for invalid numeric strings" do
    result = registry.call("to_number", ["oops"])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  describe "to_number string parsing (OPA json.Number fidelity, verified vs opa eval 1.17)" do
    def to_number_text(string)
      registry.call("to_number", [string]).to_ruby.to_s
    end

    def to_number_undefined?(string)
      registry.call("to_number", [string]).is_a?(Ruby::Rego::UndefinedValue)
    end

    it "preserves the verbatim json.Number text instead of collapsing to a Float" do
      expect(to_number_text("1.50")).to eq("1.50")
      expect(to_number_text("100.00")).to eq("100.00")
      expect(to_number_text("0.50")).to eq("0.50")
      expect(to_number_text("1e2")).to eq("1e2")
      expect(to_number_text("1E5")).to eq("1E5")
      expect(to_number_text("1e+5")).to eq("1e+5")
      expect(to_number_text("-1.50")).to eq("-1.50")
    end

    it "preserves a signed/zero literal's exact text" do
      expect(to_number_text("-0")).to eq("-0")
      expect(to_number_text("-0.0")).to eq("-0.0")
      expect(to_number_text("0")).to eq("0")
      expect(to_number_text("0.0")).to eq("0.0")
    end

    it "keeps a large integer exact (no Float precision loss)" do
      expect(to_number_text("123456789012345678901234567890")).to eq("123456789012345678901234567890")
    end

    it "is undefined for a string OPA also rejects (not strconv.ParseFloat-finite)" do
      %w[0x1F Infinity NaN oops].each do |bad|
        expect(to_number_undefined?(bad)).to be(true), "expected to_number(#{bad.inspect}) undefined"
      end
      expect(to_number_undefined?(" 42")).to be(true) # leading whitespace
      expect(to_number_undefined?("42 ")).to be(true) # trailing whitespace
      expect(to_number_undefined?("")).to be(true)    # empty
    end

    it "rejects a malformed grammar (e.g. 1.2.3) as undefined, not a crash" do
      # Pins the gate ORDER: the grammar check must run before magnitude_within_limit?, which calls
      # BigDecimal(text) and would RAISE ArgumentError (escaping the registry = DoS) on "1.2.3". The
      # strict DECIMAL_STRING gate short-circuits first, so this is a clean undefined.
      expect { registry.call("to_number", ["1.2.3"]) }.not_to raise_error
      expect(to_number_undefined?("1.2.3")).to be(true)
      expect(to_number_undefined?("1e")).to be(true)
      expect(to_number_undefined?("--1")).to be(true)
    end

    it "deliberately rejects a ParseFloat-finite-but-non-JSON form OPA accepts in comparison" do
      # OPA's to_number gates defined-ness on Go strconv.ParseFloat (lenient: accepts leading zeros,
      # a leading +, and bare dots) while storing the ORIGINAL text as a json.Number. So in OPA these
      # are usable in comparison/arithmetic (to_number("007") == 7 is true) yet CRASH on marshal
      # ("json: invalid number literal"). Faithfully storing the verbatim text would reintroduce exactly
      # the unmarshalable-Number serializer DoS that #128 closed, so the gem instead accepts only the
      # strict JSON-number grammar and routes these to undefined. This is more-strict, not "safe": it
      # flips these inputs to undefined, which changes allow vs deny rules by polarity. Verified vs
      # opa eval 1.17 (defined-in-comparison there; deliberately undefined here).
      %w[007 00 1. .5 +5 0x1p4 1_000].each do |poison|
        expect(to_number_undefined?(poison)).to be(true), "expected to_number(#{poison.inspect}) undefined"
      end
    end

    it "rejects a value that overflows float64 to infinity, but keeps in-range magnitudes" do
      expect(to_number_text("1e308")).to eq("1e308")
      expect(to_number_undefined?("1e309")).to be(true)
      expect(to_number_undefined?("1.8e308")).to be(true)
      expect(to_number_text("1e-300")).to eq("1e-300")
    end

    it "rejects a plain integer string whose magnitude overflows float64 (OPA range-checks integers too)" do
      # OPA validates to_number's argument through strconv.ParseFloat(_, 64) regardless of integer/float
      # form, so a 360-digit integer string is undefined even though it has no exponent. A 30-digit one
      # stays exact. Both verified vs opa eval 1.17.
      expect(to_number_undefined?("1#{"0" * 360}")).to be(true)
      expect(to_number_text("123456789012345678901234567890")).to eq("123456789012345678901234567890")
    end

    it "still accepts ordinary valid numbers" do
      expect(registry.call("to_number", ["42"]).to_ruby).to eq(42)
      expect(registry.call("to_number", ["-7"]).to_ruby).to eq(-7)
      expect(registry.call("to_number", ["0.1"]).to_ruby).to eq(Rational(1, 10))
    end

    it "is undefined (not a crash) for an invalid-encoding string" do
      # An attacker-controlled input field can carry any bytes. A regex match? on an invalid-UTF-8
      # string labelled UTF-8 raises ArgumentError, which would escape the registry (it rescues only
      # BuiltinArgumentError) and abort the whole policy = DoS. The byte_safe_encoding? gate short-
      # circuits before the match, mapping it to undefined instead.
      bad = "\xFF".dup.force_encoding("UTF-8")
      expect { registry.call("to_number", [bad]) }.not_to raise_error
      expect(registry.call("to_number", [bad])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "rejects an over-tiny exponent cheaply, without materializing a giant rational (DoS guard)" do
      # OPA accepts an arbitrarily small underflow (to_number("1e-1000000000") -> "1e-1000000000",
      # verbatim) because it never realizes the value. The gem would, on the first comparison, call
      # BigDecimal(text).to_r -> Rational(1, 10**1_000_000_000), a ~415 MB allocation. The magnitude
      # cap rejects it before build_number realizes anything. Deliberately more-strict than OPA here,
      # same residual as the JSON decoder's magnitude cap; the bound is the DoS defense, not fidelity.
      expect(to_number_undefined?("1e-1000000000")).to be(true)
      expect(to_number_undefined?("1e1000000000")).to be(true)
      expect(to_number_undefined?("9#{"9" * 30_103}")).to be(true) # 30104-digit integer, over the cap
      expect(to_number_text("1e-400")).to eq("1e-400") # within the cap: accepted, like OPA
    end
  end

  it "casts values to string" do
    expect(registry.call("cast_string", [true]).to_ruby).to eq("true")
    expect(registry.call("cast_string", [12]).to_ruby).to eq("12")
    expect(registry.call("cast_string", [nil]).to_ruby).to eq("null")
  end

  it "casts values to boolean" do
    expect(registry.call("cast_boolean", ["true"]).to_ruby).to be(true)
    expect(registry.call("cast_boolean", ["false"]).to_ruby).to be(false)
    expect(registry.call("cast_boolean", [1]).to_ruby).to be(true)
    expect(registry.call("cast_boolean", [0]).to_ruby).to be(false)
  end

  it "raises for invalid boolean casts" do
    yes_result = registry.call("cast_boolean", ["yes"])
    two_result = registry.call("cast_boolean", [2])

    expect(yes_result).to be_a(Ruby::Rego::UndefinedValue)
    expect(two_result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "casts arrays and sets" do
    expect(registry.call("cast_array", [Set.new([1, 2])]).to_ruby).to match_array([1, 2])
    expect(registry.call("cast_set", [[1, 2]]).to_ruby).to eq(Set.new([1, 2]))
  end

  it "raises for invalid array casts" do
    result = registry.call("cast_array", [{ "a" => 1 }])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "raises for invalid set casts" do
    result = registry.call("cast_set", [{ "a" => 1 }])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "casts objects" do
    expect(registry.call("cast_object", [{ "a" => 1 }]).to_ruby).to eq({ "a" => 1 })
  end

  it "raises for invalid object casts" do
    result = registry.call("cast_object", [[1]])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "allows repeated registration" do
    expect { Ruby::Rego::Builtins::Comparisons.register! }.not_to raise_error
    expect { Ruby::Rego::Builtins::Comparisons.register! }.not_to raise_error
  end
end

# rubocop:enable Metrics/BlockLength
