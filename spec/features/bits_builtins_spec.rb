# frozen_string_literal: true

require "spec_helper"

BITS_BUILTINS_POLICY = <<~REGO
  package bits

  masked := bits.and(input.flags, 12)

  combined := bits.or(input.flags, 1)

  shifted := bits.lsh(input.flags, 2)
REGO

RSpec.describe "bits builtins (integration)" do
  def evaluate(rule, input)
    Ruby::Rego.evaluate(BITS_BUILTINS_POLICY, input: input, query: "data.bits.#{rule}")
  end

  it "evaluates bitwise operations through the evaluator" do
    expect(evaluate("masked", { "flags" => 10 }).value.to_ruby).to eq(8)
    expect(evaluate("combined", { "flags" => 10 }).value.to_ruby).to eq(11)
    expect(evaluate("shifted", { "flags" => 10 }).value.to_ruby).to eq(40)
  end
end
