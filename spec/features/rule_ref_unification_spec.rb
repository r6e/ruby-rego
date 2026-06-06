# frozen_string_literal: true

require "spec_helper"

# Unifying a pattern against a bare same-package rule reference (`x = some_rule`)
# must resolve the rule, not treat the rule name as a fresh unification variable.
# Previously the rule name was shadowed by an undefined unification local, so
# `x = o` returned undefined and `[a, b] = o` corrupted results with sentinel
# objects. Expected values pinned against `opa eval` (OPA 1.17.0).

RULE_REF_UNIFY_POLICY = <<~REGO
  package t

  o := 5

  result := r if {
    r = o
  }
REGO

RULE_REF_UNIFY_ARRAY_POLICY = <<~REGO
  package t

  pair := [1, 2]

  result := s if {
    [a, b] = pair
    s := [a, b]
  }
REGO

RULE_REF_UNIFY_OBJECT_POLICY = <<~REGO
  package t

  obj := {"k": 9}

  result := x if {
    {"k": x} = obj
  }
REGO

# The rule reference may be on either side of the unification.
RULE_REF_UNIFY_LHS_POLICY = <<~REGO
  package t

  o := 7

  result := r if {
    o = r
  }
REGO

# The same fix applies inside comprehension and `every` bodies (they shadow
# unification locals through the shared LocalShadowing mixin).
RULE_REF_UNIFY_COMPREHENSION_POLICY = <<~REGO
  package t

  o := 5

  result := s if {
    s := {x | x = o}
  }
REGO

RULE_REF_UNIFY_EVERY_POLICY = <<~REGO
  package t

  import future.keywords

  o := 5

  result if {
    every n in [1, 2] {
      r = o
      r == 5
      n == n
    }
  }
REGO

# A genuine local unification variable still binds (regression guard).
LOCAL_UNIFY_POLICY = <<~REGO
  package t

  result := y if {
    x = 3
    y = x
  }
REGO

# rubocop:disable Metrics/BlockLength
RSpec.describe "unification against a rule reference" do
  it "resolves a scalar rule reference (`x = rule`)" do
    result = evaluate_policy(RULE_REF_UNIFY_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to eq(5)
  end

  it "destructures an array rule reference (`[a, b] = rule`)" do
    result = evaluate_policy(RULE_REF_UNIFY_ARRAY_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to eq([1, 2])
  end

  it "destructures an object rule reference (`{\"k\": x} = rule`)" do
    result = evaluate_policy(RULE_REF_UNIFY_OBJECT_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to eq(9)
  end

  it "resolves a rule reference on the left of the unification" do
    result = evaluate_policy(RULE_REF_UNIFY_LHS_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to eq(7)
  end

  it "resolves a rule reference inside a comprehension body" do
    result = evaluate_policy(RULE_REF_UNIFY_COMPREHENSION_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to contain_exactly(5)
  end

  it "resolves a rule reference inside an every body" do
    result = evaluate_policy(RULE_REF_UNIFY_EVERY_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to be(true)
  end

  it "still binds genuine local unification variables" do
    result = evaluate_policy(LOCAL_UNIFY_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to eq(3)
  end
end
# rubocop:enable Metrics/BlockLength
