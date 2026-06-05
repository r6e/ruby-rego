# frozen_string_literal: true

require "spec_helper"

JSON_PATH_BUILTINS_POLICY = <<~REGO
  package jsonpaths

  public_view := json.filter(input.record, ["name", "tags/0"])

  redacted := json.remove(input.record, ["ssn", "tags/1"])
REGO

RSpec.describe "json path builtins (integration)" do
  def evaluate(rule, input)
    Ruby::Rego.evaluate(JSON_PATH_BUILTINS_POLICY, input: input, query: "data.jsonpaths.#{rule}")
  end

  let(:record) do
    { "name" => "alice", "ssn" => "123-45-6789", "tags" => %w[admin staff temp] }
  end

  it "projects only the requested paths through the evaluator" do
    expect(evaluate("public_view", { "record" => record }).value.to_ruby)
      .to eq("name" => "alice", "tags" => ["admin"])
  end

  it "redacts the requested paths through the evaluator (array reindexes)" do
    expect(evaluate("redacted", { "record" => record }).value.to_ruby)
      .to eq("name" => "alice", "tags" => %w[admin temp])
  end
end
