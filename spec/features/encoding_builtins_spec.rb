# frozen_string_literal: true

require "spec_helper"

ENCODING_BUILTINS_POLICY = <<~REGO
  package encoding

  marshaled := json.marshal(input.doc)

  decoded := json.unmarshal(input.json)

  over_threshold := json.unmarshal(input.json) > 1000

  token := base64.encode(input.secret)

  hexed := hex.encode(input.secret)

  query := urlquery.encode(input.raw)

  compact := base64url.encode_no_pad(input.secret)

  params := urlquery.encode_object({"tag": {input.t1, input.t2}, "page": input.page})

  parsed := urlquery.decode_object(input.query_string)
REGO

# rubocop:disable Metrics/BlockLength
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

  # A large unmarshaled number compares correctly instead of collapsing to Float::INFINITY and
  # leaving the comparison undefined — a deny guard like `count > limit` no longer fails open.
  it "compares a huge unmarshaled number without failing open (matching OPA)" do
    expect(evaluate("over_threshold", { "json" => "1e999" }).value.to_ruby).to be(true)
    expect(evaluate("over_threshold", { "json" => "1.50" }).value.to_ruby).to be(false)
  end

  it "base64- and hex-encodes input" do
    expect(evaluate("token", { "secret" => "hello" }).value.to_ruby).to eq("aGVsbG8=")
    expect(evaluate("hexed", { "secret" => "hello" }).value.to_ruby).to eq("68656c6c6f")
  end

  it "url-query-encodes input" do
    expect(evaluate("query", { "raw" => "a b&c" }).value.to_ruby).to eq("a+b%26c")
  end

  it "base64url-encodes without padding through the evaluator" do
    expect(evaluate("compact", { "secret" => "hello world" }).value.to_ruby).to eq("aGVsbG8gd29ybGQ")
  end

  it "encodes an object (with a set literal) to a sorted query string through the evaluator" do
    result = evaluate("params", { "t1" => "z", "t2" => "a", "page" => "2" })
    expect(result.value.to_ruby).to eq("page=2&tag=a&tag=z")
  end

  it "decodes a query string to an object of value arrays through the evaluator" do
    result = evaluate("parsed", { "query_string" => "k=v1&k=v2&j=x" })
    expect(result.value.to_ruby).to eq("k" => %w[v1 v2], "j" => ["x"])
  end
end
# rubocop:enable Metrics/BlockLength
