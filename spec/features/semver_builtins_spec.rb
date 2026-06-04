# frozen_string_literal: true

require "spec_helper"

SEMVER_BUILTINS_POLICY = <<~REGO
  package semvers

  well_formed if semver.is_valid(input.version)

  newer if semver.compare(input.version, input.minimum) > 0
REGO

RSpec.describe "semver builtins (integration)" do
  def evaluate(rule, input)
    Ruby::Rego.evaluate(SEMVER_BUILTINS_POLICY, input: input, query: "data.semvers.#{rule}")
  end

  it "validates a version through the evaluator" do
    expect(evaluate("well_formed", { "version" => "1.4.0-rc.1" }).value.to_ruby).to be(true)
    expect(evaluate("well_formed", { "version" => "1.4" })).to be_nil
  end

  it "compares versions through the evaluator" do
    expect(evaluate("newer", { "version" => "2.1.0", "minimum" => "2.0.0" }).value.to_ruby).to be(true)
    expect(evaluate("newer", { "version" => "1.9.0", "minimum" => "2.0.0" })).to be_nil
  end
end
