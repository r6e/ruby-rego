# frozen_string_literal: true

require "spec_helper"

RULE_HEAD_REFERENCE_POLICY = <<~REGO
  package head_refs

  fruit[input.color].shade := "bright" if input.color
  fruit[input.color].size := input.size if input.color
REGO

RULE_HEAD_REFERENCE_CONFLICT_POLICY = <<~REGO
  package head_refs_conflict

  fruit[input.color].meta.size := 1 if input.color
  fruit[input.color].meta.size := 2 if input.color
REGO

RSpec.describe "Rule head references" do
  it "evaluates dynamic head references" do
    input = { "color" => "red", "size" => 3 }

    result = evaluate_policy(RULE_HEAD_REFERENCE_POLICY, input: input, query: "data.head_refs.fruit")

    expect(result.value.to_ruby).to eq({ "red" => { "shade" => "bright", "size" => 3 } })
  end

  it "returns undefined when head reference key is undefined" do
    result = evaluate_policy(RULE_HEAD_REFERENCE_POLICY, input: {}, query: "data.head_refs.fruit")

    expect(result.undefined?).to be(true)
  end

  it "raises on conflicting nested head references" do
    input = { "color" => "red" }

    expect do
      evaluate_policy(RULE_HEAD_REFERENCE_CONFLICT_POLICY, input: input, query: "data.head_refs_conflict.fruit")
    end
      .to raise_error(Ruby::Rego::EvaluationError, /Conflicting object key/)
  end
end
