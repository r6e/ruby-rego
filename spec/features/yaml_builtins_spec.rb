# frozen_string_literal: true

require "spec_helper"

# yaml.marshal / yaml.unmarshal / yaml.is_valid. OPA implements these via
# sigs.k8s.io/yaml (yaml.v2 over a JSON round-trip); expected values pinned against
# `opa eval` (OPA 1.17.0).

YAML_POLICY = <<~REGO
  package t

  marshalled := yaml.marshal(input.value)

  unmarshalled := yaml.unmarshal(input.text)

  valid := yaml.is_valid(input.text)
REGO

# rubocop:disable Metrics/BlockLength
RSpec.describe "yaml builtins" do
  # The raw marshal result: nil when the rule is undefined (e.g. an unmarshalable value).
  def marshal_result(value)
    evaluate_policy(YAML_POLICY, input: { "value" => value }, query: "data.t.marshalled")
  end

  def marshal(value)
    marshal_result(value).value.to_ruby
  end

  # The raw rule result: nil when the rule is undefined, a Value otherwise (so a
  # defined YAML `null` is distinguishable from an undefined result).
  def unmarshal_result(text)
    evaluate_policy(YAML_POLICY, input: { "text" => text }, query: "data.t.unmarshalled")
  end

  def unmarshal(text)
    unmarshal_result(text)&.value&.to_ruby
  end

  def valid?(text)
    evaluate_policy(YAML_POLICY, input: { "text" => text }, query: "data.t.valid").value.to_ruby
  end

  describe "yaml.marshal" do
    it "sorts object keys and uses two-space indentation" do
      expect(marshal({ "b" => 1, "a" => 2 })).to eq("a: 2\nb: 1\n")
    end

    it "emits block sequences and null" do
      expect(marshal({ "x" => [1, "two", true, nil] })).to eq("x:\n- 1\n- two\n- true\n- null\n")
    end

    it "formats floats with Go's shortest 'g' rules" do
      expect(marshal(1.0)).to eq("1\n")
      expect(marshal(1.5)).to eq("1.5\n")
      expect(marshal(1_000_000.0)).to eq("1e+06\n")
      expect(marshal(123_456_789.0)).to eq("1.23456789e+08\n")
      expect(marshal(0.0001)).to eq("0.0001\n")
    end

    it "double-quotes strings that would otherwise resolve to another type" do
      expect(marshal("123")).to eq("\"123\"\n")
      expect(marshal("true")).to eq("\"true\"\n")
      expect(marshal("yes")).to eq("\"yes\"\n")
      expect(marshal("")).to eq("\"\"\n")
      expect(marshal("2020-01-01")).to eq("\"2020-01-01\"\n")
    end

    it "leaves plain strings unquoted and single-quotes structurally unsafe ones" do
      expect(marshal("hello")).to eq("hello\n")
      expect(marshal({ "a" => "x: y" })).to eq("a: 'x: y'\n")
    end

    # A prefixed-overflow token (0x… past uint64) resolves back to a string, not a number,
    # so it round-trips unquoted — go-yaml's emitter does not quote it. Verified vs opa eval
    # 1.17.1 (yaml.marshal("0x10000000000000000") == "0x10000000000000000\n").
    it "emits a prefixed-overflow string unquoted (it no longer resolves to a number)" do
      expect(marshal("0x10000000000000000")).to eq("0x10000000000000000\n")
      expect(marshal("-0x8000000000000001")).to eq("-0x8000000000000001\n")
    end

    it "uses a block literal for multi-line strings" do
      expect(marshal({ "k" => "line1\nline2" })).to eq("k: |-\n  line1\n  line2\n")
    end

    it "emits empty collections in flow style" do
      expect(marshal({ "empty_map" => {}, "empty_arr" => [] })).to eq("empty_arr: []\nempty_map: {}\n")
    end

    it "stringifies, sorts and quotes non-string object keys" do
      expect(marshal({ 1 => "x" })).to eq("\"1\": x\n")
      expect(marshal({ true => "y", 1.5 => "z" })).to eq("\"1.5\": z\n\"true\": \"y\"\n")
      expect(marshal({ nil => "n" })).to eq("\"null\": \"n\"\n")
    end

    it "replaces invalid UTF-8 bytes with the replacement character (matching OPA)" do
      expect(marshal("\xFF".b)).to eq("�\n")
    end

    it "is undefined (not a crash) for a set with a non-finite, unsortable element" do
      expect(marshal_result(Set[1.0, Float::NAN, 2.0])).to be_nil
      expect(marshal_result(Set[[Float::NAN], [1.0]])).to be_nil # nested in a sorted array
    end

    it "emits set elements in deterministic OPA order (sorted, type-ranked), not insertion order" do
      expect(marshal(Set[3, 1, 2])).to eq("- 1\n- 2\n- 3\n")
      expect(marshal(Set["c", "a", "b"])).to eq("- a\n- b\n- c\n")
      expect(marshal(Set[2, "a", 1, "b"])).to eq("- 1\n- 2\n- a\n- b\n")
    end

    it "orders object keys by yaml.v2 natural sort (numeric-aware), not lexicographically" do
      expect(marshal({ "item10" => 1, "item2" => 2, "item1" => 3 })).to eq("item1: 3\nitem2: 2\nitem10: 1\n")
      expect(marshal({ 10 => "a", 2 => "b", 1 => "c" })).to eq("\"1\": c\n\"2\": b\n\"10\": a\n")
    end

    it "orders a non-letter key before a letter key (matching OPA's keyList)" do
      expect(marshal({ "_x" => 1, "Ax" => 2 })).to eq("_x: 1\nAx: 2\n")
    end

    # Documented divergence: yaml.v2's int64 key sorter wraps at 2^63, so OPA orders these
    # huge-numeric keys backwards; this implementation sorts them numerically (correctly).
    it "sorts >= 2^63 numeric keys numerically (diverging from OPA's int64 wraparound)" do
      expect(marshal({ "9300000000000000000" => 1, "8000000000000000000" => 2 }))
        .to eq("\"8000000000000000000\": 2\n\"9300000000000000000\": 1\n")
    end

    it "ranks composite set elements as OPA does: array < object < set" do
      expect(marshal(Set[{ "a" => 2 }, Set[2, 3]])).to eq("- a: 2\n- - 2\n  - 3\n")
      expect(marshal(Set[{ "a" => 1 }, [9]])).to eq("- - 9\n- a: 1\n")
      expect(marshal(Set[Set[1], { "a" => 1 }, [9]])).to eq("- - 9\n- a: 1\n- - 1\n")
    end

    it "orders object-valued set elements by their keys' term order, not stringified keys" do
      expect(marshal(Set[{ 10 => "a" }, { 2 => "b" }])).to eq("- \"2\": b\n- \"10\": a\n")
      expect(marshal(Set[{ true => "xx" }, { 1 => "yy" }])).to eq("- \"true\": xx\n- \"1\": yy\n")
    end
  end

  describe "yaml.unmarshal" do
    it "parses scalars, mappings and sequences" do
      expect(unmarshal("a: 1\nb: two")).to eq({ "a" => 1, "b" => "two" })
      expect(unmarshal("[1, 2, 3]")).to eq([1, 2, 3])
      expect(unmarshal("just a string")).to eq("just a string")
    end

    it "resolves YAML 1.1 scalars (yes/no, hex, octal, underscores)" do
      expect(unmarshal("yes")).to be(true)
      expect(unmarshal("0x1F")).to eq(31)
      expect(unmarshal("0o17")).to eq(15)
      expect(unmarshal("1_000")).to eq(1000)
    end

    it "converts integer-valued floats to integers (the JSON round-trip)" do
      expect(unmarshal("1.0")).to eq(1)
      expect(unmarshal("1e10")).to eq(10_000_000_000)
      expect(unmarshal("1.5")).to eq(1.5)
    end

    # A 0x/0o/0b literal whose value overflows uint64 (or int64 when negative) cannot be
    # reparsed as a float by go-yaml/OPA, so it falls back to its verbatim string token
    # (sign and prefix preserved). In range it stays an exact integer. Verified vs opa
    # eval 1.17.1. (A bare decimal / leading-zero octal overflow CAN reparse as a lossy
    # float and is handled separately — not in this change.)
    it "strings a prefixed (0x/0o/0b) integer that overflows uint64, keeping in-range exact" do
      expect(unmarshal("0x10000000000000000")).to eq("0x10000000000000000")
      expect(unmarshal("-0x10000000000000000")).to eq("-0x10000000000000000")
      expect(unmarshal("+0x10000000000000000")).to eq("+0x10000000000000000")
      expect(unmarshal("0o2000000000000000000000")).to eq("0o2000000000000000000000")
      expect(unmarshal("0b1#{"0" * 64}")).to eq("0b1#{"0" * 64}")
      expect(unmarshal("1: 0x10000000000000000")).to eq({ "1" => "0x10000000000000000" })
    end

    it "keeps a prefixed integer at the uint64/int64 boundary exact (number, not string)" do
      expect(unmarshal("0xFFFFFFFFFFFFFFFF")).to eq(18_446_744_073_709_551_615) # uint64 max
      expect(unmarshal("-0x8000000000000000")).to eq(-9_223_372_036_854_775_808) # int64 min
      expect(unmarshal("-0x8000000000000001")).to eq("-0x8000000000000001") # int64 min - 1 -> string
      expect(unmarshal("0o1777777777777777777777")).to eq(18_446_744_073_709_551_615)
    end

    # go-yaml's ParseUint rejects a sign, so an explicitly +/- signed prefixed value above
    # int64 max can't be parsed as an integer (and a +signed one can't be a float either),
    # falling back to its string token — whereas the same magnitude UNSIGNED is a valid
    # uint64. Verified vs opa eval 1.17.1.
    it "strings a +signed prefixed integer above int64 max (ParseUint rejects the sign)" do
      expect(unmarshal("+0x8000000000000000")).to eq("+0x8000000000000000") # int64 max + 1, signed
      expect(unmarshal("+0o1000000000000000000000")).to eq("+0o1000000000000000000000")
      expect(unmarshal("0x8000000000000000")).to eq(9_223_372_036_854_775_808) # unsigned -> uint64
      expect(unmarshal("+0x7FFFFFFFFFFFFFFF")).to eq(9_223_372_036_854_775_807) # signed, in int64 -> ok
    end

    # An integer object key in the positive uint64-only band (int64 max < k <= uint64 max)
    # decodes to a Go uint64, which sigs.k8s.io/yaml cannot stringify as a JSON key, so the
    # whole document is undefined. An int64-range key (or one beyond uint64 max, which
    # becomes a lossy-float string key) stays defined. Verified vs opa eval 1.17.1.
    it "undefines a document with an integer key in the positive uint64-only band" do
      expect(unmarshal_result("9223372036854775808: v")).to be_nil # int64 max + 1
      expect(unmarshal_result("18446744073709551615: v")).to be_nil # uint64 max
      expect(unmarshal_result("0xFFFFFFFFFFFFFFFF: v")).to be_nil # same, hex
      expect(valid?("9223372036854775808: v")).to be(false) # is_valid agrees (total predicate)
      expect(unmarshal("9223372036854775807: v")).to eq({ "9223372036854775807" => "v" }) # int64 max
      expect(unmarshal("-9223372036854775808: v")).to eq({ "-9223372036854775808" => "v" }) # int64 min
    end

    # A +/- SIGNED integer key in the same positive uint64-only band decodes to a Go float64,
    # NOT a uint64: go-yaml's ParseInt overflows int64, ParseUint rejects the sign, and
    # ParseFloat succeeds, so the key is a (lossy-float) string and the document stays defined
    # — unlike the unsigned case above, which undefines. The lossy-float key TEXT (and, for a
    # leading-octal token, ParseFloat's decimal reinterpretation of the digits) is a deferred
    # output-formatting divergence: the gem renders its exact parsed value here. OPA defines
    # `+9223372036854775808: v` as `{"9.223372e+18":"v"}`. Verified vs opa eval 1.17.1.
    it "defines a document with a +signed integer key in the uint64 band (ParseUint rejects the sign)" do
      expect(unmarshal("+9223372036854775808: v")).to eq({ "9223372036854775808" => "v" }) # int64 max + 1
      expect(unmarshal("+18446744073709551615: v")).to eq({ "18446744073709551615" => "v" }) # uint64 max
      expect(valid?("+9223372036854775808: v")).to be(true) # is_valid agrees (total predicate)
      # Leading-octal signed key: OPA reinterprets the digits as decimal (1e21), gem keeps the
      # exact octal value 2^63 — defined either way (deferred value divergence).
      expect(unmarshal("+01000000000000000000000: v")).to eq({ "9223372036854775808" => "v" })
    end

    # The uint64-band key guard reads the key scalar's text/tag to tell a true Go uint64 from a
    # float64 key (signed, or float syntax). An ALIAS key lacks that provenance — the anchor map
    # stores resolved VALUES, not source nodes — so any non-uint64 value (a +signed integer, or
    # a float that rounds into the band) reached via an alias key is conservatively treated as a
    # uint64 and undefined here, while OPA defines it with a lossy-float key. A documented,
    # gem-more-strict deferral for an exotic input (threading anchor provenance is structural).
    # The unsigned-integer alias case is correct (both undefine); negative / in-range are defined.
    # Verified vs opa eval 1.17.1.
    it "pins the deferred divergence for a non-uint64 value in the uint64 band reached via an alias key" do
      expect(unmarshal_result("k: &x +9223372036854775808\n? *x\n: val")).to be_nil # +signed: deferred (OPA defines)
      expect(unmarshal_result("k: &x 9.223372036854776e18\n? *x\n: val")).to be_nil # float syntax: deferred
      expect(unmarshal_result("k: &x 9223372036854775808\n? *x\n: val")).to be_nil # unsigned uint64 -> undef (correct)
      expect(unmarshal("k: &x -9223372036854775808\n? *x\n: val"))
        .to eq({ "k" => -9_223_372_036_854_775_808, "-9223372036854775808" => "val" }) # int64 min -> defined
    end

    # A bare decimal / leading-octal integer above float64 max overflows go-yaml's ParseFloat
    # to ±Inf and falls back to a string (plain) or undefined (!!int) — the same string
    # fallback as 1e999, reached here through the integer path. Below the ceiling it stays a
    # number. Verified vs opa eval 1.17.1.
    it "strings a bare decimal / leading-octal integer above float64 max" do
      expect(unmarshal("1#{"0" * 400}")).to eq("1#{"0" * 400}") # 1e400, way over
      expect(unmarshal("-1#{"0" * 400}")).to eq("-1#{"0" * 400}")
      expect(unmarshal("2#{"0" * 308}")).to eq("2#{"0" * 308}") # 2e308 > float64 max
      expect(unmarshal("0#{"7" * 400}")).to eq("0#{"7" * 400}") # leading-octal, decimal-overflow
      expect(unmarshal_result("!!int 1#{"0" * 400}")).to be_nil # tag over float64 -> undefined
      expect(unmarshal("17976931348623157#{"0" * 292}")).to be_a(Integer) # ~float64 max -> still a number
    end

    it "keeps timestamps as strings and stringifies object keys" do
      expect(unmarshal("2020-01-01")).to eq("2020-01-01")
      expect(unmarshal("2020-01-01T12:30:00Z")).to eq("2020-01-01T12:30:00Z")
      expect(unmarshal("1: a")).to eq({ "1" => "a" })
    end

    it "resolves anchors/aliases and takes the first document" do
      expect(unmarshal("a: &x 1\nb: *x")).to eq({ "a" => 1, "b" => 1 })
      expect(unmarshal("---\na: 1\n---\nb: 2")).to eq({ "a" => 1 })
    end

    it "is undefined for invalid YAML or a non-finite number" do
      expect(unmarshal_result("key: : bad")).to be_nil
      expect(unmarshal_result(".inf")).to be_nil
    end

    # A plain decimal that overflows float64 (1e999) is NOT a number in go-yaml/OPA — it
    # round-trips through float64, overflows to ±Inf, and falls back to its original STRING
    # text. Verified vs opa eval 1.17.1: {"v":"1e999"} as value, "1e999" bare, "1e999" key.
    # An underflow (1e-999, 1e-400) stays a finite 0.0 and resolves to the number 0. An
    # explicit `!!float 1e999` tag, by contrast, demands a float and so is undefined.
    it "falls a float64-overflowing plain decimal back to its string text (not undefined)" do
      expect(unmarshal("v: 1e999")).to eq({ "v" => "1e999" })
      expect(unmarshal("v: -1e999")).to eq({ "v" => "-1e999" })
      expect(unmarshal("1e999")).to eq("1e999")
      expect(unmarshal("1e999: x")).to eq({ "1e999" => "x" })
    end

    it "resolves a float64-underflowing decimal to 0, and undefines an !!float overflow" do
      expect(unmarshal("v: 1e-999")).to eq({ "v" => 0 })
      expect(unmarshal("v: 1e-400")).to eq({ "v" => 0 })
      expect(unmarshal_result("v: !!float 1e999")).to be_nil
    end

    it "returns a defined null value (distinct from undefined) for null" do
      result = unmarshal_result("null")
      expect(result).not_to be_nil
      expect(result.value).to be_a(Ruby::Rego::NullValue)
    end

    it "decodes an empty document as a defined null, not undefined (matching OPA)" do
      ["---\n", "", "# comment only\n"].each do |doc|
        result = unmarshal_result(doc)
        expect(result).not_to(be_nil, "#{doc.inspect} should be defined")
        expect(result.value).to be_a(Ruby::Rego::NullValue)
      end
    end

    it "round-trips through marshal" do
      original = { "name" => "svc", "ports" => [80, 443], "enabled" => true, "ratio" => 1.5 }
      expect(unmarshal(marshal(original))).to eq(original)
    end
  end

  describe "merge keys, edge cases and DoS bounds" do
    it "applies a plain merge key but treats a quoted one as an ordinary key" do
      expect(unmarshal("base: &b {a: 1}\nm:\n  <<: *b\n  c: 2")).to eq(
        { "base" => { "a" => 1 }, "m" => { "a" => 1, "c" => 2 } }
      )
      expect(unmarshal("\"<<\": [1, 2]")).to eq({ "<<" => [1, 2] })
    end

    it "resolves and stringifies object keys" do
      expect(unmarshal("0x1F: v")).to eq({ "31" => "v" })
      expect(unmarshal(".inf: x")).to eq({ ".inf" => "x" }) # non-finite key keeps its text
    end

    it "is undefined for an undefined alias or a non-mapping merge source" do
      expect(unmarshal_result("a: *undef")).to be_nil
      expect(valid?("a: *undef")).to be(false)
      expect(unmarshal_result("<<: 5")).to be_nil
    end

    it "yields undefined rather than crashing on pathologically deep nesting" do
      deep = ("[" * 5000) + ("]" * 5000)
      expect(unmarshal_result(deep)).to be_nil
      expect(valid?(deep)).to be(false)
    end

    it "yields undefined for a cyclic anchor instead of overflowing the stack" do
      expect(unmarshal_result("a: &a {b: *a}")).to be_nil
      expect(valid?("a: &a {b: *a}")).to be(false)
    end

    it "normalizes a non-finite float key to its canonical form" do
      expect(unmarshal(".Inf: x")).to eq({ ".inf" => "x" })
      expect(unmarshal("+.inf: x")).to eq({ ".inf" => "x" })
      expect(unmarshal("-.inf: x")).to eq({ "-.inf" => "x" })
      expect(unmarshal(".NaN: x")).to eq({ ".nan" => "x" })
    end

    it "stringifies finite numeric keys" do
      expect(unmarshal("1.5: v")).to eq({ "1.5" => "v" })
      expect(unmarshal("1.0: v")).to eq({ "1" => "v" }) # integer-valued float key collapses
    end

    it "is undefined for a null or composite object key (not a valid JSON key)" do
      expect(unmarshal_result("null: z")).to be_nil
      expect(unmarshal_result("~: z")).to be_nil
      expect(unmarshal_result("[1, 2]: z")).to be_nil
    end

    it "honors explicit core tags, erroring on an uncoercible value (matching OPA)" do
      expect(unmarshal('!!int "5"')).to eq(5)
      expect(unmarshal("!!str 123")).to eq("123")
      expect(unmarshal("!!float 3")).to eq(3)
      expect(unmarshal('!!bool "yes"')).to be(true)
      expect(unmarshal("!!null ~")).to be_nil
      expect(unmarshal("!!binary aGVsbG8=")).to eq("hello") # base64-decoded, like OPA
      expect(unmarshal_result('!!int "abc"')).to be_nil
      expect(unmarshal_result("!!null x")).to be_nil
      expect(unmarshal_result("!!binary xyz")).to be_nil
    end

    # An !!int has no float/string fallback: a value outside the Go int64/uint64 range is
    # undefined (go-yaml ParseInt/ParseUint both fail and the tag forbids any other type),
    # regardless of base. In range it stays exact. Verified vs opa eval 1.17.1.
    it "undefines an !!int outside the int64/uint64 range, any base" do
      expect(unmarshal_result("!!int 18446744073709551616")).to be_nil # uint64 max + 1
      expect(unmarshal_result("!!int -9223372036854775809")).to be_nil # int64 min - 1
      expect(unmarshal_result("!!int 0x10000000000000000")).to be_nil  # hex over uint64
      expect(unmarshal_result("!!int 0o2000000000000000000000")).to be_nil # octal over uint64
      expect(unmarshal_result("!!int 0b1#{"0" * 64}")).to be_nil # binary over uint64
      expect(unmarshal_result("!!int +9223372036854775808")).to be_nil # +signed past int64 max
      expect(valid?("!!int 18446744073709551616")).to be(false) # is_valid agrees
      expect(unmarshal("!!int 18446744073709551615")).to eq(18_446_744_073_709_551_615)
      expect(unmarshal("!!int -9223372036854775808")).to eq(-9_223_372_036_854_775_808)
      expect(unmarshal("!!int 9223372036854775808")).to eq(9_223_372_036_854_775_808) # unsigned uint64
      expect(unmarshal("!!int 0xFF")).to eq(255)
    end

    # go-yaml dispatches numeric coercion on a scalar's FIRST byte (yaml.v2 resolveTable):
    # only a sign, digit, or dot opens the number path. A leading underscore is NOT a numeric
    # lead, so go-yaml leaves the scalar a string and the !!int/!!float tag mismatch undefines
    # it — even though an interior or trailing underscore is a valid digit separator. The tag
    # paths must apply this gate before stripping underscores. Verified vs opa eval 1.17.1.
    it "undefines an !!int / !!float whose token does not start with a numeric lead" do
      expect(unmarshal_result("!!int _5")).to be_nil # leading underscore
      expect(unmarshal_result("!!int __7")).to be_nil
      expect(unmarshal_result("!!int _0x5")).to be_nil
      expect(unmarshal_result("!!float _5.0")).to be_nil
      expect(valid?("!!int _5")).to be(false) # is_valid agrees
      # Sign/digit/dot leads stay valid; interior and trailing separators are fine.
      expect(unmarshal("!!int 1_0")).to eq(10)
      expect(unmarshal("!!int 5_")).to eq(5)
      expect(unmarshal("!!int +_5")).to eq(5) # sign lead, then separator
      expect(unmarshal("!!float +_5.0")).to eq(5)
    end

    # `!!float` coerces an integer-resolved value to float64: go-yaml resolves the token as an
    # integer first (ParseInt→ParseUint→ParseFloat), then float-coerces it. An int64-range
    # integer of ANY base (incl. 0x/0o/0b) coerces to a float; but an UNSIGNED uint64-band value
    # resolves as a Go uint64, which has no float coercion → undefined. A signed or out-of-uint64
    # value resolves via ParseFloat and is a float already. The coerced value's TEXT is lossy
    # (int64 max → OPA 9223372036854776000) — a deferred divergence, so assert polarity not text.
    # Verified vs opa eval 1.17.1.
    it "coerces an integer-resolved !!float per go-yaml's int64/uint64 boundary" do
      expect(unmarshal("!!float 0x5")).to eq(5) # hex int → float
      expect(unmarshal("!!float 0o7")).to eq(7) # octal int → float
      expect(unmarshal("!!float 0b101")).to eq(5) # binary int → float
      expect(unmarshal_result("!!float 9223372036854775808")).to be_nil # unsigned uint64 band → undef
      expect(unmarshal_result("!!float 18446744073709551615")).to be_nil # uint64 max → undef
      expect(unmarshal_result("!!float 0xFFFFFFFFFFFFFFFF")).to be_nil # uint64 hex → undef (a uint64)
      expect(unmarshal_result("!!float +0x8000000000000000")).to be_nil # signed hex → ParseFloat rejects
      expect(valid?("!!float 9223372036854775808")).to be(false) # is_valid agrees
      # Defined-number cases (lossy text deferred): int64 max, int64 min, signed/over-uint64 → float.
      [
        "!!float 9223372036854775807", "!!float -9223372036854775808",
        "!!float +9223372036854775808", "!!float 18446744073709551616"
      ].each { |doc| expect(unmarshal(doc)).to be_a(Numeric), "#{doc} should be a defined number" }
    end

    # A float64-overflowing !!float is undefined in EVERY position. In value position
    # `reject_non_finite` already caught the ±Inf; in KEY position the non-finite float was
    # being canonicalized to a ".inf" string key before that check ran, leaving the document
    # wrongly defined. The tag path now undefines the overflow directly. (A genuine `.inf`
    # literal key stays defined as `{".inf":...}`.) Verified vs opa eval 1.17.1.
    it "undefines a float64-overflowing !!float in key position, not just value position" do
      expect(unmarshal_result("!!float 1e309: v")).to be_nil # over float64 max, key
      expect(unmarshal_result("!!float 1#{"0" * 400}: v")).to be_nil # integer-form overflow, key
      expect(unmarshal_result("!!float 1e309")).to be_nil # value position too
      expect(valid?("!!float 1e309: v")).to be(false) # is_valid agrees
      # A genuine infinity/NaN (literal or !!float-tagged) is a valid float64: undefined as a
      # value (JSON can't represent it), but a defined ".inf"/".nan" string in key position.
      expect(unmarshal(".inf: v")).to eq({ ".inf" => "v" })
      expect(unmarshal("!!float .inf: v")).to eq({ ".inf" => "v" })
      expect(unmarshal("!!float .nan: v")).to eq({ ".nan" => "v" })
      expect(unmarshal_result("!!float .inf")).to be_nil # value position
    end

    # A float-resolved object key (a !!float tag, or plain float syntax) that rounds into the
    # positive uint64-only band is a Go float64 key, which stringifies fine -> defined. Only an
    # UNSIGNED INTEGER-resolved key in that band is an unstringifiable Go uint64 -> undefined.
    # The key guard must not misclassify a rounded float as a uint64. Key TEXT is lossy (OPA:
    # "9.223372e+18"), a deferred divergence, so assert polarity. Verified vs opa eval 1.17.1.
    it "defines a float-resolved object key that rounds into the uint64 band" do
      expect(unmarshal_result("!!float 9223372036854775807: v")).not_to be_nil # !!float tag, rounds to 2^63
      expect(unmarshal_result("9.223372036854776e18: v")).not_to be_nil # plain float syntax, same value
      expect(unmarshal_result("1.0e19: v")).not_to be_nil
      # Integer-resolved unsigned uint64-band keys stay undefined (regression guard).
      expect(unmarshal_result("9223372036854775808: v")).to be_nil # plain integer -> uint64
      expect(unmarshal_result("!!int 9223372036854775808: v")).to be_nil # !!int -> uint64
    end

    # A bare decimal / leading-zero octal beyond the int64/uint64 range parses to its exact
    # bignum here, where go-yaml reparses it as a lossy float64 (e.g. 18446744073709552000).
    # That output-formatting divergence is deferred to the number sweep; pin the current
    # behavior so the deferred fix is explicit, not accidental.
    it "returns an exact bignum for a bare decimal / leading-octal overflow (deferred float-path)" do
      expect(unmarshal("18446744073709551616")).to eq(18_446_744_073_709_551_616) # decimal, over uint64
      expect(unmarshal("99999999999999999999")).to eq(99_999_999_999_999_999_999)
      expect(unmarshal("02000000000000000000000")).to be_a(Integer) # leading-zero octal overflow
      # An over-uint64 (but <= float64 max) integer KEY stays defined with the exact bignum
      # text here; go-yaml renders the lossy float (e.g. "1.8446744e+19"). Deferred with the
      # value-path formatting; pinned so the deferred fix is explicit.
      expect(unmarshal("18446744073709551616: v")).to eq({ "18446744073709551616" => "v" })
    end

    # Ruby < 3.4's Float() rejects a bare leading/trailing dot, so these are normalized
    # before parsing to stay consistent with OPA across every supported Ruby version.
    it "accepts dot-edge floats (5. / .5 / 5.e3 / .5e2), matching OPA, plain and tagged" do
      expect(unmarshal("5.")).to eq(5)
      expect(unmarshal(".5")).to eq(0.5)
      expect(unmarshal("5.e3")).to eq(5000)
      expect(unmarshal(".5e2")).to eq(50)
      expect(unmarshal("+.5")).to eq(0.5)
      expect(unmarshal("-.5")).to eq(-0.5)
      expect(unmarshal("-5.")).to eq(-5)
      expect(unmarshal("!!float 5.")).to eq(5)
      expect(unmarshal("!!float -5.")).to eq(-5)
    end

    it "strips underscores anywhere in a number, like yaml.v2 (1_e2 == 100)" do
      # yaml.v2's resolve.go removes every '_' before parsing, so this matches OPA — not
      # the stricter YAML-spec "between digits only" rule.
      expect(unmarshal("1_e2")).to eq(100)
      expect(unmarshal("1__0")).to eq(10)
      expect(unmarshal("_1")).to eq("_1")
    end

    it "is undefined for a non-finite value" do
      expect(unmarshal_result("x: .inf")).to be_nil
    end
  end

  describe "yaml.is_valid" do
    it "is true for valid YAML and false otherwise" do
      expect(valid?("a: 1")).to be(true)
      expect(valid?("42")).to be(true)
      expect(valid?("key: : bad")).to be(false)
    end

    it "is a total predicate: a non-string runtime value is false, not undefined" do
      expect(valid?(123)).to be(false)
      expect(valid?(["a"])).to be(false)
    end
  end
end
# rubocop:enable Metrics/BlockLength
