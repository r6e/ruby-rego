# frozen_string_literal: true

require "spec_helper"

GLOB_BUILTINS_POLICY = <<~REGO
  package glob

  host_allowed if glob.match("*.example.com", ["."], input.host)

  path_allowed if glob.match("/api/**", ["/"], input.path)

  safe := glob.quote_meta(input.raw)
REGO

RSpec.describe "glob builtins (integration)" do
  def evaluate(rule, input)
    Ruby::Rego.evaluate(GLOB_BUILTINS_POLICY, input: input, query: "data.glob.#{rule}")
  end

  it "matches a hostname glob through the evaluator" do
    expect(evaluate("host_allowed", { "host" => "api.example.com" }).value.to_ruby).to be(true)
    expect(evaluate("host_allowed", { "host" => "a.b.example.com" })).to be_nil
  end

  it "matches a path glob with a custom delimiter" do
    expect(evaluate("path_allowed", { "path" => "/api/v1/users" }).value.to_ruby).to be(true)
  end

  it "quotes glob metacharacters" do
    expect(evaluate("safe", { "raw" => "a*b" }).value.to_ruby).to eq('a\\*b')
  end
end
