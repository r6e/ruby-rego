# frozen_string_literal: true

require "spec_helper"

FUNCTIONS_POLICY = <<~REGO
  package funcs

  sum_two := 1 + 2

  total := sum(input.values)

  sorted := sort(input.values)

  lowered := lower(input.user)

  prefix_ok { startswith(input.path, "/api") }

  joined := concat("-", split(input.user, "-"))

  splits := split(input.user, "-")
REGO

FUNCTIONS_INPUT = {
  "values" => [3, 1, 2],
  "user" => "Admin-User",
  "path" => "/api/v1",
  "map" => { "present" => "value" }
}.freeze

RSpec.describe "Functions arithmetic" do
  it "evaluates arithmetic rules" do
    result = evaluate_policy(FUNCTIONS_POLICY, input: FUNCTIONS_INPUT, query: "data.funcs.sum_two")

    expect(result.value.to_ruby).to eq(3)
  end
end

RSpec.describe "Functions aggregates" do
  it "evaluates aggregate and collection builtins" do
    total_result = evaluate_policy(FUNCTIONS_POLICY, input: FUNCTIONS_INPUT, query: "data.funcs.total")
    sorted_result = evaluate_policy(FUNCTIONS_POLICY, input: FUNCTIONS_INPUT, query: "data.funcs.sorted")

    expect(total_result.value.to_ruby).to eq(6)
    expect(sorted_result.value.to_ruby).to eq([1, 2, 3])
  end
end

RSpec.describe "Functions strings" do
  it "evaluates string builtins" do
    lowered_result = evaluate_policy(FUNCTIONS_POLICY, input: FUNCTIONS_INPUT, query: "data.funcs.lowered")
    split_result = evaluate_policy(FUNCTIONS_POLICY, input: FUNCTIONS_INPUT, query: "data.funcs.splits")

    expect(lowered_result.value.to_ruby).to eq("admin-user")
    expect(split_result.value.to_ruby).to eq(%w[Admin User])
  end
end

RSpec.describe "Functions predicates" do
  it "handles predicate rules using builtins" do
    result = evaluate_policy(FUNCTIONS_POLICY, input: FUNCTIONS_INPUT, query: "data.funcs.prefix_ok")

    expect(result.value.to_ruby).to be(true)
  end
end

RSpec.describe "Functions concat" do
  it "joins split values using concat" do
    result = evaluate_policy(FUNCTIONS_POLICY, input: FUNCTIONS_INPUT, query: "data.funcs.joined")

    expect(result.value.to_ruby).to eq("Admin-User")
  end
end

RSpec.describe "Functions errors" do
  it "raises type errors for invalid builtin arguments" do
    policy = <<~REGO
      package funcs

      bad := sum([1, "two"])
    REGO

    expect { evaluate_policy(policy, query: "data.funcs.bad") }
      .to raise_error(Ruby::Rego::TypeError)
  end
end
