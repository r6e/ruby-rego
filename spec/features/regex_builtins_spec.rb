# frozen_string_literal: true

require "spec_helper"

REGEX_BUILTINS_POLICY = <<~REGO
  package regexes

  looks_like_id if regex.match("^[a-z]+-[0-9]+$", input.id)

  parts := regex.split("[,;]", input.csv)

  numbers := regex.find_n("[0-9]+", input.text, -1)

  valid_pattern if regex.is_valid(input.pattern)
REGO

RSpec.describe "regex builtins (integration)" do
  def evaluate(rule, input)
    Ruby::Rego.evaluate(REGEX_BUILTINS_POLICY, input: input, query: "data.regexes.#{rule}")
  end

  it "matches an anchored pattern against input" do
    expect(evaluate("looks_like_id", { "id" => "user-42" }).value.to_ruby).to be(true)
    expect(evaluate("looks_like_id", { "id" => "User-42" })).to be_nil
  end

  it "splits input on a character class" do
    expect(evaluate("parts", { "csv" => "a,b;c" }).value.to_ruby).to eq(%w[a b c])
  end

  it "finds all numeric runs in input" do
    expect(evaluate("numbers", { "text" => "a1 b22 c333" }).value.to_ruby).to eq(%w[1 22 333])
  end

  it "validates a pattern supplied via input" do
    expect(evaluate("valid_pattern", { "pattern" => "a(b)c" }).value.to_ruby).to be(true)
    expect(evaluate("valid_pattern", { "pattern" => "a(b" })).to be_nil
  end
end
