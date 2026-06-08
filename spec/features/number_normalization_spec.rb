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
end
# rubocop:enable Metrics/BlockLength
