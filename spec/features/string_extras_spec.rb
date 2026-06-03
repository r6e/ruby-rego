# frozen_string_literal: true

require "spec_helper"

STRING_EXTRAS_POLICY = <<~REGO
  package strings

  slug := replace(input.text, " ", "-")

  stem := trim_suffix(trim_prefix(input.path, "/"), "/")

  flipped := strings.reverse(input.text)

  hits := strings.count(input.text, input.needle)

  positions := indexof_n(input.text, input.needle)
REGO

RSpec.describe "string extra builtins (integration)" do
  def evaluate(rule, input)
    Ruby::Rego.evaluate(STRING_EXTRAS_POLICY, input: input, query: "data.strings.#{rule}")
  end

  it "replaces and trims input strings" do
    expect(evaluate("slug", { "text" => "a b c" }).value.to_ruby).to eq("a-b-c")
    expect(evaluate("stem", { "path" => "/api/" }).value.to_ruby).to eq("api")
  end

  it "reverses, counts, and indexes input" do
    input = { "text" => "banana", "needle" => "a" }
    expect(evaluate("flipped", input).value.to_ruby).to eq("ananab")
    expect(evaluate("hits", input).value.to_ruby).to eq(3)
    expect(evaluate("positions", input).value.to_ruby).to eq([1, 3, 5])
  end
end
