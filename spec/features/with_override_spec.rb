# frozen_string_literal: true

require "spec_helper"

# OPA-parity behaviour for the `with` keyword that the basic input/data and
# function-replacement paths do not yet cover. Expected values are pinned
# against `opa eval` (OPA 1.17.0).

# `mock_count` calls `count`; while the replacement's own body runs, the `count`
# override must be suspended so the inner call hits the real builtin.
# opa eval => 4 (3 + 1). Previously stack-overflowed.
WITH_RECURSION_POLICY = <<~REGO
  package t

  mock_count(x) := count(x) + 1

  f(x) := count(x)

  result := y if {
    y := f([1, 2, 3]) with count as mock_count
  }
REGO

# A replacement user-function may itself reference the replaced builtin.
# opa eval => 6 (count of 3 elements, doubled).
WITH_USER_FN_RECURSION_POLICY = <<~REGO
  package t

  double_len(xs) := count(xs) * 2

  result := y if {
    y := count([10, 20, 30]) with count as double_len
  }
REGO

# `data.t.x` is a rule; `with data.t.x as 2` must shadow the computed rule
# value. opa eval => 2. Previously returned the rule's own value (1).
WITH_VIRTUAL_EXACT_POLICY = <<~REGO
  package t

  x := 1

  result := y if {
    y := data.t.x with data.t.x as 2
  }
REGO

# The override is scoped to the path it names; sibling rules are unaffected.
# opa eval => [5, 1].
WITH_VIRTUAL_SCOPED_POLICY = <<~REGO
  package t

  x := 1

  y := 1

  result := [a, b] if {
    a := data.t.x with data.t.x as 5
    b := data.t.y
  }
REGO

# A `with data.t.x as 2` override is also honoured when the rule is referenced
# by its bare name `x` from within package `t`, not only via `data.t.x`.
# opa eval => 2.
WITH_VIRTUAL_BARE_REF_POLICY = <<~REGO
  package t

  x := 1

  result := y if {
    y := x with data.t.x as 2
  }
REGO

# Regression guard: replacing a user function with another function already
# works. opa eval => 99.
WITH_FN_REPLACE_POLICY = <<~REGO
  package t

  mock(_) := 99

  f(x) := count(x)

  result := y if {
    y := f([1, 2, 3]) with f as mock
  }
REGO

RSpec.describe "with keyword OPA parity" do
  it "evaluates a replacement's inner builtin call against the original builtin" do
    result = evaluate_policy(WITH_RECURSION_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to eq(4)
  end

  it "lets a replacement function call the function it replaces" do
    result = evaluate_policy(WITH_USER_FN_RECURSION_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to eq(6)
  end

  it "shadows a virtual-document (rule) value with the override" do
    result = evaluate_policy(WITH_VIRTUAL_EXACT_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to eq(2)
  end

  it "leaves sibling rules unaffected by a virtual-document override" do
    result = evaluate_policy(WITH_VIRTUAL_SCOPED_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to eq([5, 1])
  end

  it "honours a data-path override for a bare same-package rule reference" do
    result = evaluate_policy(WITH_VIRTUAL_BARE_REF_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to eq(2)
  end

  it "still replaces a user function with another function" do
    result = evaluate_policy(WITH_FN_REPLACE_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to eq(99)
  end
end
