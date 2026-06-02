# frozen_string_literal: true

require "spec_helper"

RSpec.describe Ruby::Rego::Evaluator::ModuleContextRegistry do
  it "returns the resolver for the longest matching package" do
    resolver_a = Object.new
    resolver_b = Object.new
    registry = described_class.new("acme" => resolver_a, "acme.authz" => resolver_b)

    expect(registry.resolver_for(%w[acme authz allow])).to be(resolver_b)
    expect(registry.resolver_for(%w[acme other])).to be(resolver_a)
  end

  it "returns nil when no package owns the keys" do
    registry = described_class.new("acme.authz" => Object.new)
    expect(registry.resolver_for(%w[other thing])).to be_nil
  end
end
