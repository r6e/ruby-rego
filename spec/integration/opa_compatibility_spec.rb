# frozen_string_literal: true

require "spec_helper"

RSpec.describe "OPA compatibility examples" do
  it "evaluates the httpapi example from OPA docs" do
    policy = read_fixture("policies/opa_httpapi.rego")
    input = load_json_fixture("data/http_request_get.json")

    result = evaluate_policy(policy, input: input, query: "data.httpapi.allow")

    expect(result.success?).to be(true)
    expect(result.value.to_ruby).to be(true)
  end

  it "denies POST requests in the httpapi example" do
    policy = read_fixture("policies/opa_httpapi.rego")
    input = load_json_fixture("data/http_request_post.json")

    result = evaluate_policy(policy, input: input, query: "data.httpapi.allow")

    expect(result.success?).to be(true)
    expect(result.value.to_ruby).to be(false)
  end

  it "returns formatted deny messages from OPA-style policies" do
    policy = read_fixture("policies/opa_deny.rego")
    input = load_json_fixture("data/users.json")

    result = evaluate_policy(policy, input: input, query: "data.opa.deny")

    expect(result.success?).to be(true)
    expect(result.value.to_ruby).to eq(Set.new(["guest user: bob"]))
  end
end
