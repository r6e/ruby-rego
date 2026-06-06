# frozen_string_literal: true

require "spec_helper"

# OPA rejects a variable in object-key position as unsafe: you cannot bind a key
# variable by destructuring an object (use `obj[k]` iteration instead). OPA emits
# `rego_unsafe_var_error: var k is unsafe`. The gem previously enumerated candidate
# keys and bound them, a non-standard extension; it now rejects them at compile
# time, matching OPA. Pinned against `opa check --strict` (OPA 1.17.0).

VAR_KEY_UNIFY_POLICY = <<~REGO
  package t

  o := {"a": 1}

  result := v if {
    {k: v} = o
  }
REGO

VAR_KEY_ASSIGN_POLICY = <<~REGO
  package t

  o := {"a": 1}

  result := v if {
    {k: v} := o
  }
REGO

VAR_KEY_SOME_POLICY = <<~REGO
  package t

  import future.keywords

  result := s if {
    s := {v | some {k: v} in input.x}
  }
REGO

# A literal object key still binds its value (regression guard).
LITERAL_KEY_POLICY = <<~REGO
  package t

  o := {"a": 5}

  result := v if {
    {"a": v} = o
  }
REGO

RSpec.describe "variable object keys" do
  it "rejects a variable object key in unification as unsafe" do
    expect { evaluate_policy(VAR_KEY_UNIFY_POLICY, query: "data.t.result") }
      .to raise_error(Ruby::Rego::CompilationError, /unbound variables.*\bk\b/)
  end

  it "rejects a variable object key in assignment as unsafe" do
    expect { evaluate_policy(VAR_KEY_ASSIGN_POLICY, query: "data.t.result") }
      .to raise_error(Ruby::Rego::CompilationError, /unbound variables.*\bk\b/)
  end

  it "rejects a variable object key in a some-in pattern as unsafe" do
    expect { evaluate_policy(VAR_KEY_SOME_POLICY, input: { "x" => [{ "a" => 1 }] }, query: "data.t.result") }
      .to raise_error(Ruby::Rego::CompilationError, /unbound variables.*\bk\b/)
  end

  it "still binds the value of a literal object key" do
    result = evaluate_policy(LITERAL_KEY_POLICY, query: "data.t.result")
    expect(result.value.to_ruby).to eq(5)
  end
end
