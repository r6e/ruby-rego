# frozen_string_literal: true

require "spec_helper"

INTEGRATION_COMBINED_FEATURES_POLICY = <<~REGO
  package integrated_combo

  user_checks[name].valid := true if {
    some name, user in input.users
    {"profile": {"tier": tier}, "roles": roles} := user
    [primary_role, _] := roles
    startswith(primary_role, "eng")
    count(roles) >= 2
    every required in input.required_roles { required in roles }
    tier >= 2
  }

  user_checks[name].role_count := count(roles) if {
    some name, user in input.users
    {"profile": _, "roles": roles} := user
  }

  simulated_valid[name] if {
    some name, _ in input.simulated.users
    user_checks[name].valid with input.required_roles as input.simulated.required_roles with input.users as input.simulated.users
  }
REGO

INTEGRATION_COMBINED_FEATURES_INPUT = {
  "users" => {
    "alice" => {
      "roles" => %w[eng_admin audit],
      "profile" => { "tier" => 3 }
    },
    "bob" => {
      "roles" => %w[eng_viewer],
      "profile" => { "tier" => 3 }
    }
  },
  "required_roles" => %w[eng_admin audit],
  "simulated" => {
    "required_roles" => %w[eng_viewer],
    "users" => {
      "alice" => {
        "roles" => %w[eng_admin audit],
        "profile" => { "tier" => 3 }
      },
      "bob" => {
        "roles" => %w[eng_viewer ops],
        "profile" => { "tier" => 3 }
      }
    }
  }
}.freeze

INTEGRATION_COMBINED_FEATURES_EXPECTED_USER_CHECKS = {
  "alice" => { "valid" => true, "role_count" => 2 },
  "bob" => { "role_count" => 1 }
}.freeze

RSpec.describe "Policy evaluation integration allow" do
  it "parses fixture policies into AST nodes" do
    allow_policy = read_fixture("policies/allow_admin.rego")

    ast_module = parse_policy(allow_policy)

    expect(ast_module.package).to match_ast(Ruby::Rego::AST::Package, path: ["auth"])
  end

  it "evaluates allow policy for admin input" do
    allow_policy = read_fixture("policies/allow_admin.rego")
    admin_input = load_json_fixture("data/admin.json")

    result = evaluate_policy(allow_policy, input: admin_input, query: "data.auth.allow")

    expect(result.success?).to be(true)
    expect(result.value.to_ruby).to be(true)
  end

  it "denies non-admin input with default" do
    allow_policy = read_fixture("policies/allow_admin.rego")
    user_input = load_yaml_fixture("data/user.yaml")

    result = evaluate_policy(allow_policy, input: user_input, query: "data.auth.allow")

    expect(result.success?).to be(true)
    expect(result.value.to_ruby).to be(false)
  end
end

RSpec.describe "Policy evaluation integration deny" do
  it "collects deny messages from partial set rules" do
    policy = read_fixture("policies/deny_ports.rego")
    input = load_json_fixture("data/open_ports.json")

    result = evaluate_policy(policy, input: input, query: "data.compliance.deny")

    expect(result.success?).to be(true)
    expect(result.value.to_ruby).to eq(Set.new(["port 22 should not be exposed"]))
  end

  it "returns undefined when no deny messages match" do
    policy = read_fixture("policies/deny_ports.rego")
    input = load_json_fixture("data/open_ports_safe.json")

    result = evaluate_policy(policy, input: input, query: "data.compliance.deny")

    expect(result).to be_nil
  end
end

RSpec.describe "Policy evaluation integration comprehensions" do
  it "evaluates comprehension policy fixtures end-to-end" do
    policy = read_fixture("policies/comprehensions.rego")
    input = load_json_fixture("data/comprehension.json")

    even_result = evaluate_policy(policy, input: input, query: "data.features.even_numbers")
    set_result = evaluate_policy(policy, input: input, query: "data.features.number_set")
    object_result = evaluate_policy(policy, input: input, query: "data.features.keyed")

    expect(even_result.value.to_ruby).to eq([2, 4])
    expect(set_result.value.to_ruby).to eq(Set.new([3, 4]))
    expect(object_result.value.to_ruby).to eq({ "a" => 10, "b" => 20 })
  end
end

RSpec.describe "Policy evaluation integration combined features" do
  it "evaluates every, rule-head references, destructuring, and built-ins with OPA-aligned semantics" do
    result = evaluate_policy(
      INTEGRATION_COMBINED_FEATURES_POLICY,
      input: INTEGRATION_COMBINED_FEATURES_INPUT,
      query: "data.integrated_combo.user_checks"
    )

    expect(result.success?).to be(true)
    expect(result.value.to_ruby).to eq(INTEGRATION_COMBINED_FEATURES_EXPECTED_USER_CHECKS)
  end
end

RSpec.describe "Policy evaluation integration combined features with overrides" do
  it "applies with overrides to referenced rules without mutating baseline behavior" do
    simulated = evaluate_policy(
      INTEGRATION_COMBINED_FEATURES_POLICY,
      input: INTEGRATION_COMBINED_FEATURES_INPUT,
      query: "data.integrated_combo.simulated_valid"
    )
    baseline = evaluate_policy(
      INTEGRATION_COMBINED_FEATURES_POLICY,
      input: INTEGRATION_COMBINED_FEATURES_INPUT,
      query: "data.integrated_combo.user_checks"
    )

    expect(simulated.success?).to be(true)
    expect(simulated.value.to_ruby).to eq(Set.new(["bob"]))
    expect(baseline.value.to_ruby).to eq(INTEGRATION_COMBINED_FEATURES_EXPECTED_USER_CHECKS)
  end
end
