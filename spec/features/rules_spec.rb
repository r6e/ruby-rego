# frozen_string_literal: true

require "spec_helper"

RULES_POLICY = <<~REGO
  package rules

  default allow := false

  allow { input.user == "admin" }
  allow { input.role == "ops" }

  roles contains "admin"
  roles contains "user"

  users["alice"] := "admin"
  users["bob"] := "user"
REGO

RSpec.describe "Rules defaults" do
  it "uses default rules when no body matches" do
    result = evaluate_policy(RULES_POLICY, input: { "user" => "guest" }, query: "data.rules.allow")

    expect(result.success?).to be(true)
    expect(result.value.to_ruby).to be(false)
  end

  it "evaluates rule bodies to true" do
    admin_result = evaluate_policy(RULES_POLICY, input: { "user" => "admin" }, query: "data.rules.allow")
    ops_result = evaluate_policy(RULES_POLICY, input: { "role" => "ops" }, query: "data.rules.allow")

    expect(admin_result.value.to_ruby).to be(true)
    expect(ops_result.value.to_ruby).to be(true)
  end
end

RSpec.describe "Rules collections" do
  it "builds partial set rules" do
    result = evaluate_policy(RULES_POLICY, query: "data.rules.roles")

    expect(result.value.to_ruby).to eq(Set.new(%w[admin user]))
  end

  it "builds partial object rules" do
    result = evaluate_policy(RULES_POLICY, query: "data.rules.users")

    expect(result.value.to_ruby).to eq({ "alice" => "admin", "bob" => "user" })
  end
end
