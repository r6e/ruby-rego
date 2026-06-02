# frozen_string_literal: true

require "spec_helper"

RSpec.describe Ruby::Rego::Evaluator::RuleValueProvider do
  it "does not collide cache entries for same rule name in different packages" do
    memo = Ruby::Rego::Memoization::Store.new

    provider_a = described_class.new(rules_by_name: { "allow" => [:rule] }, memoization: memo, package_key: "a")
    provider_b = described_class.new(rules_by_name: { "allow" => [:rule] }, memoization: memo, package_key: "b")

    fake_a = Class.new { def evaluate_group(_rules) = Ruby::Rego::Value.from_ruby("from_a") }.new
    fake_b = Class.new { def evaluate_group(_rules) = Ruby::Rego::Value.from_ruby("from_b") }.new
    provider_a.attach(fake_a)
    provider_b.attach(fake_b)

    expect(provider_a.value_for("allow").to_ruby).to eq("from_a")
    expect(provider_b.value_for("allow").to_ruby).to eq("from_b")
  end

  it "defaults package_key to an empty string when not given" do
    provider = described_class.new(rules_by_name: {}, memoization: nil)
    expect(provider.send(:package_key)).to eq("")
  end
end
