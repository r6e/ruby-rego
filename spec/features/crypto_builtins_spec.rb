# frozen_string_literal: true

require "spec_helper"

CRYPTO_BUILTINS_POLICY = <<~REGO
  package crypto

  fingerprint := crypto.sha256(input.secret)

  legacy := crypto.md5(input.secret)

  signature := crypto.hmac.sha256(input.secret, input.key)

  authentic if crypto.hmac.equal(crypto.hmac.sha256(input.secret, input.key), input.expected)
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

  # Exercises the three-segment builtin name (crypto.hmac.sha256 / crypto.hmac.equal)
  # through the full parse -> evaluate path, and their composition.
  it "computes and verifies an HMAC signature through the evaluator" do
    signature = evaluate("signature", { "secret" => "hello", "key" => "secret" }).value.to_ruby
    expect(signature).to eq("88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b")

    input = { "secret" => "hello", "key" => "secret", "expected" => signature }
    expect(evaluate("authentic", input).value.to_ruby).to be(true)

    tampered = input.merge("expected" => "#{signature.chop}0")
    expect(evaluate("authentic", tampered)).to be_nil
  end
end
