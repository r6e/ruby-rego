# frozen_string_literal: true

require "spec_helper"

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
