# frozen_string_literal: true

require "spec_helper"

CRYPTO_BUILTINS_POLICY = <<~REGO
  package crypto

  fingerprint := crypto.sha256(input.secret)

  legacy := crypto.md5(input.secret)
REGO

RSpec.describe "crypto builtins (integration)" do
  def evaluate(rule, input)
    Ruby::Rego.evaluate(CRYPTO_BUILTINS_POLICY, input: input, query: "data.crypto.#{rule}")
  end

  it "hashes input through the evaluator" do
    expect(evaluate("fingerprint", { "secret" => "abc" }).value.to_ruby)
      .to eq("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    expect(evaluate("legacy", { "secret" => "abc" }).value.to_ruby).to eq("900150983cd24fb0d6963f7d28e17f72")
  end
end
