# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
require "spec_helper"

RSpec.describe Ruby::Rego::CompiledPolicySet do
  def compiled(package_path)
    Ruby::Rego::CompiledModule.new(package_path: package_path, rules_by_name: {})
  end

  it "indexes modules by joined package key" do
    authz = compiled(%w[acme authz])
    users = compiled(%w[acme users])
    set = described_class.new([authz, users])

    expect(set.modules.length).to eq(2)
    expect(set.module_for(%w[acme authz allow])).to be(authz)
    expect(set.module_for(%w[acme users alice])).to be(users)
  end

  it "returns the longest matching package prefix" do
    parent = compiled(%w[acme])
    child = compiled(%w[acme authz])
    set = described_class.new([parent, child])

    expect(set.module_for(%w[acme authz allow])).to be(child)
    expect(set.module_for(%w[acme other])).to be(parent)
  end

  it "returns nil when no package owns the keys" do
    set = described_class.new([compiled(%w[acme authz])])
    expect(set.module_for(%w[other thing])).to be_nil
  end

  it "exposes package keys" do
    set = described_class.new([compiled(%w[acme authz])])
    expect(set.package_keys).to eq(["acme.authz"])
  end

  it "raises when two modules share a package path" do
    expect do
      described_class.new([compiled(%w[acme authz]), compiled(%w[acme authz])])
    end.to raise_error(ArgumentError, /Duplicate package key: acme.authz/)
  end

  it "returns nil when keys exactly equal a package path" do
    set = described_class.new([compiled(%w[acme authz])])
    expect(set.module_for(%w[acme authz])).to be_nil
  end

  it "finds the longest prefix regardless of insertion order" do
    parent = compiled(%w[acme])
    child = compiled(%w[acme authz])
    set = described_class.new([child, parent])

    expect(set.module_for(%w[acme authz allow])).to be(child)
    expect(set.module_for(%w[acme other])).to be(parent)
  end
end

# rubocop:enable Metrics/BlockLength
