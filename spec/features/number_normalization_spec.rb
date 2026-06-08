# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

require "spec_helper"

# OPA treats numerically-equal numbers (1 and 1.0, 1.5 and 1.50) as the same value everywhere.
# The Value layer canonicalizes them for equality/hashing while keeping the first-seen
# representation. All expected values were verified against `opa eval` 1.17.
RSpec.describe "number normalization (1 == 1.0) at the value layer" do
  def eval_rule(body)
    Ruby::Rego.evaluate("package t\nr := #{body}", query: "data.t.r")&.value&.to_ruby
  end

  it "deduplicates numerically-equal numbers in a set, keeping the first-seen form" do
    expect(eval_rule("count({1, 1.0})")).to eq(1)
    expect(eval_rule("count({1, 1.0, 1.00})")).to eq(1)
    expect(eval_rule("{1, 1.0}")).to eq(Set[1])
    expect(eval_rule("{1.0, 1}")).to eq(Set[1.0])
  end

  it "treats 1 and 1.0 as equal, including for sets" do
    expect(eval_rule("1 == 1.0")).to be(true)
    expect(eval_rule("{1} == {1.0}")).to be(true)
    expect(eval_rule("[1] == [1.0]")).to be(true)
    expect(eval_rule('{"a": 1} == {"a": 1.0}')).to be(true)
  end

  it "normalizes recursively through arrays, sets, and objects as set elements" do
    expect(eval_rule("count({[1], [1.0]})")).to eq(1)
    expect(eval_rule("count({{1}, {1.0}})")).to eq(1)
    expect(eval_rule('count({ {"a": 1}, {"a": 1.0} })')).to eq(1)
    expect(eval_rule('count({ {1: "x"}, {1.0: "x"} })')).to eq(1)
  end

  it "deduplicates in set comprehensions and partial-set rules" do
    expect(eval_rule("count({ x | some x in [1, 1.0, 1.00, 2] })")).to eq(2)
    set_rule = Ruby::Rego.evaluate("package t\nout contains 1\nout contains 1.0", query: "data.t.out")
    expect(set_rule.value.to_ruby).to eq(Set[1])
  end

  it "treats 1 and 1.0 as the same set member in either direction" do
    expect(eval_rule("1.0 in {1}")).to be(true)
    expect(eval_rule("1 in {1.0}")).to be(true)
    expect(eval_rule("9 in {1.0}")).to be(false)
  end

  it "merges numerically-equal object keys, keeping the first key form and last value" do
    expect(eval_rule('{1: "a", 1.0: "b"}')).to eq({ 1 => "b" })
    expect(eval_rule('{1.0: "a", 1: "b"}')).to eq({ 1.0 => "b" })
    expect(eval_rule('count({1: "a", 1.0: "b"})')).to eq(1)
    expect(eval_rule('object.keys({1: "a", 1.0: "b"})')).to eq(Set[1])
  end

  it "looks up object values by numeric equality (1 finds a 1.0 key and vice versa)" do
    expect(eval_rule('object.get({1.0: "v"}, 1, "default")')).to eq("v")
    expect(eval_rule('object.get({1: "v"}, 1.0, "default")')).to eq("v")
    expect(eval_rule('object.get({1.0: "v"}, 2, "default")')).to eq("default")
  end

  # Known divergences for numeric keys *duplicated/conflicting within a single construct* — rare,
  # and rooted in object-literal / partial-rule / unifier construction internals rather than the
  # value layer. Documented in CHANGELOG. These pending specs name the cases so they are not
  # re-discovered as new bugs; flip them to real expectations if the construction paths are fixed.
  describe "known numeric-key duplication/conflict limitations (see CHANGELOG)" do
    it "picks OPA's last value in a literal repeating an exact key plus a numeric alias" do
      pending("object-literal pairs.to_h collapses exact-dup keys before numeric merge; OPA gives {1: 'c'}")
      expect(eval_rule('{1: "a", 1.0: "b", 1: "c"}')).to eq({ 1 => "c" })
    end

    it "fails closed (raises a conflict) on a partial-object rule with conflicting numeric-alias keys" do
      pending("partial-rule accumulator uses raw keys, so the 1/1.0 conflict is not detected (fail-open)")
      expect do
        Ruby::Rego.evaluate("package t\np[1] := \"a\"\np[1.0] := \"b\"", query: "data.t.p")
      end.to raise_error(Ruby::Rego::EvaluationError)
    end

    it "matches an object pattern across numeric-alias keys when destructuring" do
      pending("unifier uses a raw key lookup, so the {1: x} pattern does not match a 1.0 key")
      expect(eval_rule('[x | {1: x} = {1.0: "v"}]')).to eq(["v"])
    end
  end
end
# rubocop:enable Metrics/BlockLength
