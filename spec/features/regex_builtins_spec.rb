# frozen_string_literal: true

require "spec_helper"

REGEX_BUILTINS_POLICY = <<~REGO
  package regexes

  looks_like_id if regex.match("^[a-z]+-[0-9]+$", input.id)

  parts := regex.split("[,;]", input.csv)

  numbers := regex.find_n("[0-9]+", input.text, -1)

  valid_pattern if regex.is_valid(input.pattern)

  redacted := regex.replace(input.text, "[0-9]{4}", "****")

  reordered := regex.replace(input.date, "([0-9]+)-([0-9]+)-([0-9]+)", "$3/$2/$1")
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

  it "replaces matches, expanding submatch references" do
    expect(evaluate("redacted", { "text" => "card 1234 5678" }).value.to_ruby).to eq("card **** ****")
    expect(evaluate("reordered", { "date" => "2023-01-15" }).value.to_ruby).to eq("15/01/2023")
  end
end
