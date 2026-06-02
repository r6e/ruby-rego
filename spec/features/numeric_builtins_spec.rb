# frozen_string_literal: true

require "spec_helper"

NUMERIC_BUILTINS_POLICY = <<~REGO
  package numeric

  magnitude := abs(input.delta)

  rounded := round(input.measure)

  ceiling := ceil(input.measure)

  flooring := floor(input.measure)

  span := numbers.range(input.low, input.high)
REGO

RSpec.describe "numeric builtins (integration)" do
  def evaluate(rule, input)
    Ruby::Rego.evaluate(NUMERIC_BUILTINS_POLICY, input: input, query: "data.numeric.#{rule}")
  end

  it "evaluates abs/round/ceil/floor against input" do
    input = { "delta" => -7, "measure" => 2.5 }

    expect(evaluate("magnitude", input).value.to_ruby).to eq(7)
    expect(evaluate("rounded", input).value.to_ruby).to eq(3)
    expect(evaluate("ceiling", input).value.to_ruby).to eq(3)
    expect(evaluate("flooring", input).value.to_ruby).to eq(2)
  end

  it "builds an ascending range from input bounds" do
    expect(evaluate("span", { "low" => 1, "high" => 4 }).value.to_ruby).to eq([1, 2, 3, 4])
  end

  it "builds a descending range when bounds are reversed" do
    expect(evaluate("span", { "low" => 4, "high" => 1 }).value.to_ruby).to eq([4, 3, 2, 1])
  end

  it "leaves the range rule undefined for a non-integer bound" do
    expect(evaluate("span", { "low" => 1.5, "high" => 4 })).to be_nil
  end
end
