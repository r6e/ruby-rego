# frozen_string_literal: true

require "spec_helper"

NET_BUILTINS_POLICY = <<~REGO
  package net

  in_corp_range if net.cidr_contains("10.0.0.0/8", input.client_ip)

  ranges_overlap if net.cidr_intersects(input.a, input.b)

  well_formed if net.cidr_is_valid(input.range)
REGO

RSpec.describe "net builtins (integration)" do
  def evaluate(rule, input)
    Ruby::Rego.evaluate(NET_BUILTINS_POLICY, input: input, query: "data.net.#{rule}")
  end

  it "checks CIDR membership through the evaluator" do
    expect(evaluate("in_corp_range", { "client_ip" => "10.1.2.3" }).value.to_ruby).to be(true)
    expect(evaluate("in_corp_range", { "client_ip" => "192.168.0.1" })).to be_nil
  end

  it "checks CIDR intersection through the evaluator" do
    expect(evaluate("ranges_overlap", { "a" => "10.0.0.0/8", "b" => "10.1.0.0/16" }).value.to_ruby).to be(true)
    expect(evaluate("ranges_overlap", { "a" => "10.0.0.0/16", "b" => "10.1.0.0/16" })).to be_nil
  end

  it "validates CIDR notation through the evaluator" do
    expect(evaluate("well_formed", { "range" => "192.168.0.0/24" }).value.to_ruby).to be(true)
    # is_valid is total: a bare IP is false, so the rule is undefined (body fails)
    expect(evaluate("well_formed", { "range" => "192.168.0.1" })).to be_nil
  end
end
