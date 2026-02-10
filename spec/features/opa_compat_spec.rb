# frozen_string_literal: true

require "spec_helper"

OPA_IMPORTS_POLICY = <<~REGO
  package access

  import data.roles
  import input.user

  is_admin if roles[user] == "admin"

  allow if is_admin

  allow_direct if roles[user]
REGO

OPA_IMPORT_SHADOW_POLICY = <<~REGO
  package shadow

  import data.roles

  allow {
    some roles
    roles["alice"] == "admin"
  }
REGO

OPA_RULE_SHADOW_POLICY = <<~REGO
  package shadow_rule

  roles := {"alice": "admin"}

  allow {
    some roles
    roles["alice"] == "admin"
  }
REGO

OPA_ELSE_POLICY = <<~REGO
  package else_example

  authorize := "allow" if input.user == "admin" else := "deny" if input.user == "guest" else := "unknown"
REGO

OPA_MEMBERSHIP_POLICY = <<~REGO
  package membership

  allowed := "admin" in input.roles
REGO

OPA_OBJECT_MEMBERSHIP_POLICY = <<~REGO
  package object_membership

  allowed := "admin" in input.roles
REGO

OPA_EMPTY_POLICY = <<~REGO
  package empties

  obj := {}
  s := set()
REGO

OPA_TEMPLATE_POLICY = <<~REGO
  package templates

  msg := $"User {input.user}"
  undef := $"Missing {input.missing}"
  raw := $`hello \\{world}`
REGO

OPA_UNDEFINED_EQ_POLICY = <<~REGO
  package eq

  result := input.missing == "x"
REGO

OPA_UNDEFINED_MEMBERSHIP_POLICY = <<~REGO
  package membership_undefined

  left := input.missing in input.roles
  right := "admin" in input.missing
REGO

OPA_LOGICAL_POLICY = <<~REGO
  package logical

  true_and_missing := true and input.missing
  false_and_missing := false and input.missing
  true_or_missing := true or input.missing
  false_or_missing := false or input.missing
  missing_or_true := input.missing or true
  missing_or_false := input.missing or false
  missing_and_true := input.missing and true
  missing_and_false := input.missing and false
REGO

OPA_EVERY_NEGATION_POLICY = <<~REGO
  package every_negation

  all_positive := every x in input.values { x > 0 }
  not_all_positive := not every x in input.values { x > 0 }
REGO

OPA_FUNCTION_ELSE_POLICY = <<~REGO
  package function_else

  add_one(x) := x + 1 if x > 0 else := 0

  pos := add_one(1)
  neg := add_one(-1)
REGO

OPA_FUNCTION_REFERENCE_POLICY = <<~REGO
  package func_ref

  add_one(x) := x + 1

  result := data.func_ref.add_one(1)
  result_bracket := data.func_ref["add_one"](1)
REGO

OPA_NON_COLLECTION_MEMBERSHIP_POLICY = <<~REGO
  package membership_non_collection

  result := "a" in 1
REGO

OPA_RULE_HEAD_POLICY = <<~REGO
  package fruits

  fruit.apple.seeds := 12
  fruit.apple.color := "red"
  fruit.apple.meta.owner := "bob"
  fruit.apple.meta.size := 3
  fruit.orange.color := "orange"
REGO

OPA_PARTIAL_OBJECT_CONFLICT_POLICY = <<~REGO
  package conflict

  obj["a"] := {"x": 1}
  obj["a"] := {"y": 2}
REGO

RSpec.describe "OPA imports" do
  it "resolves import aliases and direct rule references" do
    data = { "roles" => { "alice" => "admin" } }
    input = { "user" => "alice" }

    result = evaluate_policy(OPA_IMPORTS_POLICY, input: input, data: data, query: "data.access.allow")
    direct = evaluate_policy(OPA_IMPORTS_POLICY, input: input, data: data, query: "data.access.allow_direct")

    expect(result.value.to_ruby).to be(true)
    expect(direct.value.to_ruby).to be(true)
  end

  it "treats missing user keys as undefined" do
    data = { "roles" => { "alice" => "admin", "bob" => "user" } }
    input = { "user" => "carol" }

    direct = evaluate_policy(OPA_IMPORTS_POLICY, input: input, data: data, query: "data.access.allow_direct")

    expect(direct.undefined?).to be(true)
  end
end

RSpec.describe "OPA import shadowing" do
  it "treats local variables as shadowing imports" do
    data = { "roles" => { "alice" => "admin" } }

    result = evaluate_policy(
      OPA_IMPORT_SHADOW_POLICY,
      input: {},
      data: data,
      query: "data.shadow.allow"
    )

    expect(result.undefined?).to be(true)
  end
end

RSpec.describe "OPA rule shadowing" do
  it "treats local variables as shadowing rules" do
    result = evaluate_policy(OPA_RULE_SHADOW_POLICY, query: "data.shadow_rule.allow")

    expect(result.undefined?).to be(true)
  end
end

RSpec.describe "OPA else" do
  it "evaluates else chains in order" do
    admin = evaluate_policy(OPA_ELSE_POLICY, input: { "user" => "admin" }, query: "data.else_example.authorize")
    guest = evaluate_policy(OPA_ELSE_POLICY, input: { "user" => "guest" }, query: "data.else_example.authorize")
    other = evaluate_policy(OPA_ELSE_POLICY, input: { "user" => "bob" }, query: "data.else_example.authorize")

    expect(admin.value.to_ruby).to eq("allow")
    expect(guest.value.to_ruby).to eq("deny")
    expect(other.value.to_ruby).to eq("unknown")
  end
end

RSpec.describe "OPA membership" do
  it "checks membership with in operator" do
    input = { "roles" => %w[admin user] }
    result = evaluate_policy(OPA_MEMBERSHIP_POLICY, input: input, query: "data.membership.allowed")

    expect(result.value.to_ruby).to be(true)
  end
end

RSpec.describe "OPA object membership" do
  it "checks membership against object keys" do
    input = { "roles" => { "admin" => false, "user" => true } }
    result = evaluate_policy(
      OPA_OBJECT_MEMBERSHIP_POLICY,
      input: input,
      query: "data.object_membership.allowed"
    )

    expect(result.value.to_ruby).to be(true)
  end
end

RSpec.describe "OPA empty objects and sets" do
  it "distinguishes empty objects and sets" do
    obj = evaluate_policy(OPA_EMPTY_POLICY, query: "data.empties.obj")
    set = evaluate_policy(OPA_EMPTY_POLICY, query: "data.empties.s")

    expect(obj.value.to_ruby).to eq({})
    expect(set.value.to_ruby).to eq(Set.new)
  end
end

RSpec.describe "OPA template strings" do
  it "interpolates values and handles undefined" do
    input = { "user" => "alice" }

    msg = evaluate_policy(OPA_TEMPLATE_POLICY, input: input, query: "data.templates.msg")
    undefined_result = evaluate_policy(OPA_TEMPLATE_POLICY, input: input, query: "data.templates.undef")
    raw = evaluate_policy(OPA_TEMPLATE_POLICY, input: input, query: "data.templates.raw")

    expect(msg.value.to_ruby).to eq("User alice")
    expect(undefined_result.value.to_ruby).to eq("Missing <undefined>")
    expect(raw.value.to_ruby).to eq("hello {world}")
  end
end

RSpec.describe "OPA undefined comparisons" do
  it "treats undefined comparisons as undefined" do
    result = evaluate_policy(OPA_UNDEFINED_EQ_POLICY, input: {}, query: "data.eq.result")

    expect(result.undefined?).to be(true)
  end
end

RSpec.describe "OPA undefined membership" do
  it "treats undefined membership as undefined" do
    input = { "roles" => %w[admin user] }
    left = evaluate_policy(
      OPA_UNDEFINED_MEMBERSHIP_POLICY,
      input: input,
      query: "data.membership_undefined.left"
    )
    right = evaluate_policy(
      OPA_UNDEFINED_MEMBERSHIP_POLICY,
      input: input,
      query: "data.membership_undefined.right"
    )

    expect(left.undefined?).to be(true)
    expect(right.undefined?).to be(true)
  end
end

RSpec.describe "OPA logical operators" do
  def logical_result(name)
    evaluate_policy(OPA_LOGICAL_POLICY, input: {}, query: "data.logical.#{name}")
  end

  it "short-circuits and on and" do
    expect(logical_result("true_and_missing").undefined?).to be(true)
    expect(logical_result("false_and_missing").value.to_ruby).to be(false)
    expect(logical_result("missing_and_true").undefined?).to be(true)
    expect(logical_result("missing_and_false").value.to_ruby).to be(false)
  end

  it "short-circuits and on or" do
    expect(logical_result("true_or_missing").value.to_ruby).to be(true)
    expect(logical_result("false_or_missing").undefined?).to be(true)
    expect(logical_result("missing_or_true").value.to_ruby).to be(true)
    expect(logical_result("missing_or_false").undefined?).to be(true)
  end
end

RSpec.describe "OPA negated every" do
  it "evaluates negated every expressions" do
    all_positive = evaluate_policy(
      OPA_EVERY_NEGATION_POLICY,
      input: { "values" => [1, 2] },
      query: "data.every_negation.all_positive"
    )
    not_all_positive = evaluate_policy(
      OPA_EVERY_NEGATION_POLICY,
      input: { "values" => [1, 2, -1] },
      query: "data.every_negation.not_all_positive"
    )

    expect(all_positive.value.to_ruby).to be(true)
    expect(not_all_positive.value.to_ruby).to be(true)
  end
end

RSpec.describe "OPA function else" do
  it "uses else clauses for function rules" do
    pos = evaluate_policy(OPA_FUNCTION_ELSE_POLICY, query: "data.function_else.pos")
    neg = evaluate_policy(OPA_FUNCTION_ELSE_POLICY, query: "data.function_else.neg")

    expect(pos.value.to_ruby).to eq(2)
    expect(neg.value.to_ruby).to eq(0)
  end
end

RSpec.describe "OPA function reference calls" do
  it "resolves data references when calling functions" do
    result = evaluate_policy(OPA_FUNCTION_REFERENCE_POLICY, query: "data.func_ref.result")
    bracket = evaluate_policy(OPA_FUNCTION_REFERENCE_POLICY, query: "data.func_ref.result_bracket")

    expect(result.value.to_ruby).to eq(2)
    expect(bracket.value.to_ruby).to eq(2)
  end
end

RSpec.describe "OPA membership non-collection" do
  it "treats non-collection membership as undefined" do
    result = evaluate_policy(
      OPA_NON_COLLECTION_MEMBERSHIP_POLICY,
      query: "data.membership_non_collection.result"
    )

    expect(result.undefined?).to be(true)
  end
end

RSpec.describe "OPA rule head references" do
  it "expands dotted rule heads into nested objects" do
    result = evaluate_policy(OPA_RULE_HEAD_POLICY, query: "data.fruits.fruit")

    expect(result.value.to_ruby).to eq(
      {
        "apple" => {
          "seeds" => 12,
          "color" => "red",
          "meta" => { "owner" => "bob", "size" => 3 }
        },
        "orange" => { "color" => "orange" }
      }
    )
  end
end

RSpec.describe "OPA partial object conflicts" do
  it "raises when partial object keys conflict" do
    expect { evaluate_policy(OPA_PARTIAL_OBJECT_CONFLICT_POLICY, query: "data.conflict.obj") }
      .to raise_error(Ruby::Rego::EvaluationError, /Conflicting object key/)
  end
end
