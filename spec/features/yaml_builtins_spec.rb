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
  def marshal(value)
    evaluate_policy(YAML_POLICY, input: { "value" => value }, query: "data.t.marshalled").value.to_ruby
  end

  def unmarshal(text)
    result = evaluate_policy(YAML_POLICY, input: { "text" => text }, query: "data.t.unmarshalled")
    result&.value&.to_ruby
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
      expect(unmarshal("key: : bad")).to be_nil
      expect(unmarshal(".inf")).to be_nil
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
      expect(unmarshal("a: *undef")).to be_nil
      expect(valid?("a: *undef")).to be(false)
      expect(unmarshal("<<: 5")).to be_nil
    end

    it "yields undefined rather than crashing on pathologically deep nesting" do
      deep = ("[" * 5000) + ("]" * 5000)
      expect(unmarshal(deep)).to be_nil
      expect(valid?(deep)).to be(false)
    end

    it "yields undefined for a cyclic anchor instead of overflowing the stack" do
      expect(unmarshal("a: &a {b: *a}")).to be_nil
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

    it "is undefined for a non-finite value" do
      expect(unmarshal("x: .inf")).to be_nil
    end
  end

  describe "yaml.is_valid" do
    it "is true for valid YAML and false otherwise" do
      expect(valid?("a: 1")).to be(true)
      expect(valid?("42")).to be(true)
      expect(valid?("key: : bad")).to be(false)
    end
  end
end
# rubocop:enable Metrics/BlockLength
