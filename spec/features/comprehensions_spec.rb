# frozen_string_literal: true

require "spec_helper"

COMPREHENSIONS_POLICY = <<~REGO
  package features

  evens := [n | some n in input.numbers; n % 2 == 0]

  large := {n | some n in input.numbers; n > 2}

  pairs := {k: v | some k in input.keys; v := input.map[k]}
REGO

COMPREHENSIONS_INPUT = {
  "numbers" => [1, 2, 3, 4],
  "keys" => %w[a b],
  "map" => { "a" => 10, "b" => 20 }
}.freeze

RSpec.describe "Comprehensions arrays" do
  it "builds array comprehensions" do
    result = evaluate_policy(COMPREHENSIONS_POLICY, input: COMPREHENSIONS_INPUT, query: "data.features.evens")

    expect(result.value.to_ruby).to eq([2, 4])
  end
end

RSpec.describe "Comprehensions sets" do
  it "builds set comprehensions" do
    result = evaluate_policy(COMPREHENSIONS_POLICY, input: COMPREHENSIONS_INPUT, query: "data.features.large")

    expect(result.value.to_ruby).to eq(Set.new([3, 4]))
  end
end

RSpec.describe "Comprehensions objects" do
  it "builds object comprehensions" do
    result = evaluate_policy(COMPREHENSIONS_POLICY, input: COMPREHENSIONS_INPUT, query: "data.features.pairs")

    expect(result.value.to_ruby).to eq({ "a" => 10, "b" => 20 })
  end
end
