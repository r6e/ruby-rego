# frozen_string_literal: true

require "spec_helper"

# rubocop:disable Metrics/BlockLength

# When non-integer literals became arbitrary-precision Number objects, builtins that type-dispatch on
# Float/Integer had to learn about Number too. These cover the totality (no crash) and no-regression
# guarantees for that surface. Expected values verified against `opa eval` 1.17.
RSpec.describe "number model — builtin interaction" do
  def eval_rule(body)
    Ruby::Rego.evaluate("package t\nr := #{body}", query: "data.t.r")&.value&.to_ruby
  end

  describe "round / ceil / floor never raise FloatDomainError on a beyond-Float-range Number" do
    it "returns a finite integer instead of crashing the policy (totality)" do
      expect { eval_rule("round(1e400)") }.not_to raise_error
      expect(eval_rule("round(1e400)")).to be_a(Integer)
      expect(eval_rule("ceil(1e400)")).to be_a(Integer)
      expect(eval_rule("floor(1e400)")).to be_a(Integer)
      expect(eval_rule("abs(-1e400)")).to eq(10**400)
    end

    it "still matches OPA for normal-magnitude values (half-away-from-zero)" do
      expect(eval_rule("round(2.5)")).to eq(3)
      expect(eval_rule("round(-2.5)")).to eq(-3)
      expect(eval_rule("ceil(-1.2)")).to eq(-1)
      expect(eval_rule("floor(-1.8)")).to eq(-2)
      expect(eval_rule("abs(-2.0)")).to eq(2)
    end
  end

  describe "integer-valued Number literals are accepted where an integer is required" do
    it "numbers.range / range_step accept float-form bounds (matching OPA)" do
      expect(eval_rule("numbers.range(1, 3.0)")).to eq([1, 2, 3])
      expect(eval_rule("numbers.range(1.0, 3)")).to eq([1, 2, 3])
      expect(eval_rule("numbers.range_step(1, 7.0, 3.0)")).to eq([1, 4, 7])
    end

    it "bits operations accept float-form operands" do
      expect(eval_rule("bits.and(6.0, 3)")).to eq(2)
      expect(eval_rule("bits.or(4.0, 1)")).to eq(5)
      expect(eval_rule("bits.lsh(4.0, 1)")).to eq(8)
    end

    it "format_int accepts a float-form integer argument" do
      expect(eval_rule("format_int(255.0, 16)")).to eq("ff")
    end

    it "a non-integer-valued bound is undefined, matching OPA" do
      expect(eval_rule("numbers.range(1, 3.5)")).to be_nil
    end
  end

  describe "yaml.marshal renders a Number through float64, like OPA" do
    it "drops trailing zeros, collapses integer-valued, and uses Go scientific notation" do
      expect(eval_rule("yaml.marshal(1.50)")).to eq("1.5\n")
      expect(eval_rule("yaml.marshal(2.0)")).to eq("2\n")
      expect(eval_rule("yaml.marshal(1e308)")).to eq("1e+308\n")
      expect(eval_rule('yaml.marshal({"a": 1.5})')).to eq("a: 1.5\n")
    end
  end

  describe "json.match_schema treats an integer-valued Number as an integer (gojsonschema)" do
    let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

    # OPA type-rejects a scalar document, so a Number reaches integer_doc? only nested in a document.
    def integer_match(number)
      schema = '{"type":"object","properties":{"x":{"type":"integer"}}}'
      registry.call("json.match_schema", [{ "x" => number }, schema]).to_ruby.first
    end

    it "matches an integer-valued Number but not a fractional one" do
      expect(integer_match(Ruby::Rego::Number.literal("2.0"))).to be(true)
      expect(integer_match(Ruby::Rego::Number.literal("2.5"))).to be(false)
    end
  end

  describe "aggregates and ordering over Numbers" do
    it "sum / max / min / sort behave like OPA" do
      expect(eval_rule("sum([1.5, 2.5])")).to eq(4)
      expect(eval_rule("max([1.5, 2.5])")).to eq(Ruby::Rego::Number.literal("2.5"))
      expect(eval_rule("sort([3.3, 1.1, 2.2])").map(&:to_s)).to eq(%w[1.1 2.2 3.3])
    end
  end
end

# rubocop:enable Metrics/BlockLength
