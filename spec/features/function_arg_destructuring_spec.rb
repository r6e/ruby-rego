# frozen_string_literal: true

require "spec_helper"

# Destructuring patterns in function-argument position (`f({"a": x})`, `f([a, b])`).
# The evaluator already unifies each head-arg pattern against the call argument;
# these exercise that the safety checker treats the pattern's value-position
# variables as bound. Expected values pinned against `opa eval` (OPA 1.17.0).

FN_DESTRUCTURE_OBJECT_POLICY = <<~REGO
  package t

  f({"a": v}) := v

  result := f(input.o)
REGO

FN_DESTRUCTURE_ARRAY_POLICY = <<~REGO
  package t

  f([a, b]) := [b, a]

  result := f(input.x)
REGO

FN_DESTRUCTURE_NESTED_POLICY = <<~REGO
  package t

  f({"a": {"b": v}}) := v

  result := f(input.o)
REGO

FN_DESTRUCTURE_TWO_KEY_POLICY = <<~REGO
  package t

  f({"a": x, "b": y}) := x + y

  result := f(input.o)
REGO

FN_DESTRUCTURE_MIXED_POLICY = <<~REGO
  package t

  f([a, {"k": b}]) := [a, b]

  result := f(input.x)
REGO

# Exact-shape: an extra key means the pattern does not match, so the call
# falls through to the default. opa eval => "no".
FN_DESTRUCTURE_EXTRA_KEY_POLICY = <<~REGO
  package t

  f({"a": v}) := v

  default f(_) := "no"

  result := f(input.o)
REGO

# Variable object-pattern KEYS (`f({k: v})`) are rejected at compile time, the
# same as variable object keys in any pattern position (see
# variable_object_key_spec.rb). OPA treats `f({k: v})` slightly differently here
# (it binds both as arguments, reporting `unused argument k` under
# `opa check --strict`, then evaluates the call to `undefined`), but the gem's
# uniform rejection of variable object keys is the closer match overall.
FN_DESTRUCTURE_VAR_KEY_POLICY = <<~REGO
  package t

  f({k: v}) := v

  result := f(input.o)
REGO

# rubocop:disable Metrics/BlockLength
RSpec.describe "function-argument destructuring" do
  it "binds a value-position variable from an object pattern argument" do
    result = evaluate_policy(FN_DESTRUCTURE_OBJECT_POLICY, input: { "o" => { "a" => 5 } }, query: "data.t.result")
    expect(result.value.to_ruby).to eq(5)
  end

  it "binds variables from an array pattern argument" do
    result = evaluate_policy(FN_DESTRUCTURE_ARRAY_POLICY, input: { "x" => [1, 2] }, query: "data.t.result")
    expect(result.value.to_ruby).to eq([2, 1])
  end

  it "binds a variable nested inside object patterns" do
    result = evaluate_policy(FN_DESTRUCTURE_NESTED_POLICY, input: { "o" => { "a" => { "b" => 9 } } },
                                                           query: "data.t.result")
    expect(result.value.to_ruby).to eq(9)
  end

  it "binds multiple value-position variables from one object pattern" do
    result = evaluate_policy(FN_DESTRUCTURE_TWO_KEY_POLICY, input: { "o" => { "a" => 3, "b" => 4 } },
                                                            query: "data.t.result")
    expect(result.value.to_ruby).to eq(7)
  end

  it "binds variables across mixed array and object patterns" do
    result = evaluate_policy(FN_DESTRUCTURE_MIXED_POLICY, input: { "x" => [1, { "k" => 2 }] }, query: "data.t.result")
    expect(result.value.to_ruby).to eq([1, 2])
  end

  it "falls through to the default when an extra key breaks the exact shape" do
    result = evaluate_policy(FN_DESTRUCTURE_EXTRA_KEY_POLICY, input: { "o" => { "a" => 5, "b" => 6 } },
                                                              query: "data.t.result")
    expect(result.value.to_ruby).to eq("no")
  end

  it "rejects a variable object-pattern key as unsafe (known OPA divergence)" do
    expect { evaluate_policy(FN_DESTRUCTURE_VAR_KEY_POLICY, input: { "o" => { "a" => 1 } }, query: "data.t.result") }
      .to raise_error(Ruby::Rego::CompilationError, /unbound variables k/)
  end
end
# rubocop:enable Metrics/BlockLength
