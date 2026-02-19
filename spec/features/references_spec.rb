# frozen_string_literal: true

require "spec_helper"

REFERENCES_POLICY = <<~REGO
  package refs

  is_admin { data.roles.alice == "admin" }

  first_resource := input.resources[0].name

  tagged { input.resources[0].tags["env"] == input.env }

  lead := input.team.leads[1]

  enabled { input.enabled }

  optional { input.optional }

  missing_tag { input.resources[0].tags["missing"] == "x" }
REGO

REFERENCES_DATA = {
  "roles" => {
    "alice" => "admin",
    "bob" => "user"
  }
}.freeze

REFERENCES_INPUT = {
  "user" => "alice",
  "env" => "prod",
  "enabled" => false,
  "optional" => nil,
  "resources" => [
    { "name" => "server-1", "tags" => { "env" => "prod" } }
  ],
  "team" => { "leads" => %w[alice bob] }
}.freeze

RSpec.describe "References basics" do
  it "resolves data and input references" do
    result = evaluate_policy(
      REFERENCES_POLICY,
      input: REFERENCES_INPUT,
      data: REFERENCES_DATA,
      query: "data.refs.is_admin"
    )

    expect(result.success?).to be(true)
    expect(result.value.to_ruby).to be(true)
  end
end

RSpec.describe "References paths" do
  it "navigates nested references with dots and brackets" do
    resource_result = evaluate_policy(
      REFERENCES_POLICY,
      input: REFERENCES_INPUT,
      data: REFERENCES_DATA,
      query: "data.refs.first_resource"
    )
    lead_result = evaluate_policy(
      REFERENCES_POLICY,
      input: REFERENCES_INPUT,
      data: REFERENCES_DATA,
      query: "data.refs.lead"
    )

    expect(resource_result.value.to_ruby).to eq("server-1")
    expect(lead_result.value.to_ruby).to eq("bob")
  end

  it "handles nested object references" do
    result = evaluate_policy(
      REFERENCES_POLICY,
      input: REFERENCES_INPUT,
      data: REFERENCES_DATA,
      query: "data.refs.tagged"
    )

    expect(result.value.to_ruby).to be(true)
  end
end

RSpec.describe "References missing paths" do
  it "treats missing references as undefined in rule bodies" do
    result = evaluate_policy(
      REFERENCES_POLICY,
      input: REFERENCES_INPUT,
      data: REFERENCES_DATA,
      query: "data.refs.missing_tag"
    )

    expect(result).to be_nil
  end
end

RSpec.describe "References falsy values" do
  it "treats false references as undefined in rule bodies" do
    result = evaluate_policy(
      REFERENCES_POLICY,
      input: REFERENCES_INPUT,
      data: REFERENCES_DATA,
      query: "data.refs.enabled"
    )

    expect(result).to be_nil
  end

  it "treats null references as undefined in rule bodies" do
    result = evaluate_policy(
      REFERENCES_POLICY,
      input: REFERENCES_INPUT,
      data: REFERENCES_DATA,
      query: "data.refs.optional"
    )

    expect(result).to be_nil
  end
end
