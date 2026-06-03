# frozen_string_literal: true

require "spec_helper"

ENCODING_BUILTINS_POLICY = <<~REGO
  package encoding

  marshaled := json.marshal(input.doc)

  decoded := json.unmarshal(input.json)

  token := base64.encode(input.secret)

  hexed := hex.encode(input.secret)

  query := urlquery.encode(input.raw)
REGO

RSpec.describe "encoding builtins (integration)" do
  def evaluate(rule, input)
    Ruby::Rego.evaluate(ENCODING_BUILTINS_POLICY, input: input, query: "data.encoding.#{rule}")
  end

  it "marshals an input document with sorted keys" do
    result = evaluate("marshaled", { "doc" => { "b" => 1, "a" => 2 } })
    expect(result.value.to_ruby).to eq('{"a":2,"b":1}')
  end

  it "round-trips JSON through unmarshal" do
    result = evaluate("decoded", { "json" => '{"k":[true,null]}' })
    expect(result.value.to_ruby).to eq("k" => [true, nil])
  end

  it "leaves the unmarshal rule undefined for invalid JSON" do
    expect(evaluate("decoded", { "json" => "not json" })).to be_nil
  end

  it "base64- and hex-encodes input" do
    expect(evaluate("token", { "secret" => "hello" }).value.to_ruby).to eq("aGVsbG8=")
    expect(evaluate("hexed", { "secret" => "hello" }).value.to_ruby).to eq("68656c6c6f")
  end

  it "url-query-encodes input" do
    expect(evaluate("query", { "raw" => "a b&c" }).value.to_ruby).to eq("a+b%26c")
  end
end
