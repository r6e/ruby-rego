# frozen_string_literal: true

require "spec_helper"

# Destructuring patterns in `some … in` membership declarations
# (`some [a, b] in coll`, `some {"k": v} in coll`, `some k, [a, b] in coll`).
# Each collection element is unified against the pattern; non-matching elements
# are skipped. Expected values pinned against `opa eval` (OPA 1.17.0).

SOME_IN_ARRAY_PATTERN_POLICY = <<~REGO
  package t

  import future.keywords

  result[a] := b if {
    some [a, b] in input.pairs
  }
REGO

# A non-matching element (wrong length) is skipped, not an error.
SOME_IN_SKIP_NONMATCH_POLICY = <<~REGO
  package t

  import future.keywords

  result := s if {
    s := {a | some [a, _] in input.x}
  }
REGO

SOME_IN_OBJECT_PATTERN_POLICY = <<~REGO
  package t

  import future.keywords

  result := s if {
    s := {v | some {"k": v} in input.x}
  }
REGO

SOME_IN_KEY_AND_PATTERN_POLICY = <<~REGO
  package t

  import future.keywords

  result[k] := pair if {
    some k, [a, b] in input.o
    pair := [a, b]
  }
REGO

SOME_IN_FILTER_POLICY = <<~REGO
  package t

  import future.keywords

  result := s if {
    s := {a | some [a, b] in input.x; b > 1}
  }
REGO

RSpec.describe "some-in destructuring" do
  it "destructures an array pattern over an array of pairs" do
    result = evaluate_policy(SOME_IN_ARRAY_PATTERN_POLICY, input: { "pairs" => [["x", 1], ["y", 2]] },
                                                           query: "data.t.result")
    expect(result.value.to_ruby).to eq("x" => 1, "y" => 2)
  end

  it "skips elements that do not match the pattern shape" do
    result = evaluate_policy(SOME_IN_SKIP_NONMATCH_POLICY, input: { "x" => [["p", 1], [1, 2, 3], ["q", 4]] },
                                                           query: "data.t.result")
    expect(result.value.to_ruby).to contain_exactly("p", "q")
  end

  it "destructures an object pattern" do
    result = evaluate_policy(SOME_IN_OBJECT_PATTERN_POLICY, input: { "x" => [{ "k" => 1 }, { "k" => 2 }] },
                                                            query: "data.t.result")
    expect(result.value.to_ruby).to contain_exactly(1, 2)
  end

  it "destructures the value position of a key, value membership" do
    result = evaluate_policy(SOME_IN_KEY_AND_PATTERN_POLICY, input: { "o" => { "p" => [1, 2], "q" => [3, 4] } },
                                                             query: "data.t.result")
    expect(result.value.to_ruby).to eq("p" => [1, 2], "q" => [3, 4])
  end

  it "binds pattern variables usable in the rest of the body" do
    result = evaluate_policy(SOME_IN_FILTER_POLICY, input: { "x" => [["p", 1], ["q", 5]] }, query: "data.t.result")
    expect(result.value.to_ruby).to contain_exactly("q")
  end
end
