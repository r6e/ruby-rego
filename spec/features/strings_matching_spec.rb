# frozen_string_literal: true

require "spec_helper"

STRINGS_MATCHING_POLICY = <<~REGO
  package strings_match

  redacted := strings.replace_n({"secret": "***", "token": "###"}, input.text)

  trusted := strings.any_prefix_match(input.host, ["10.", "192.168."])

  image := strings.any_suffix_match(input.file, [".png", ".jpg"])
REGO

RSpec.describe "strings matching builtins (integration)" do
  def evaluate(rule, input)
    Ruby::Rego.evaluate(STRINGS_MATCHING_POLICY, input: input, query: "data.strings_match.#{rule}")
  end

  it "applies replace_n through the evaluator" do
    result = evaluate("redacted", { "text" => "secret token secret" })
    expect(result.value.to_ruby).to eq("*** ### ***")
  end

  it "evaluates any_prefix_match against a base array" do
    expect(evaluate("trusted", { "host" => "192.168.1.5" }).value.to_ruby).to be(true)
    expect(evaluate("trusted", { "host" => "8.8.8.8" }).value.to_ruby).to be(false)
  end

  it "evaluates any_suffix_match against a base array" do
    expect(evaluate("image", { "file" => "logo.png" }).value.to_ruby).to be(true)
    expect(evaluate("image", { "file" => "notes.txt" }).value.to_ruby).to be(false)
  end
end
