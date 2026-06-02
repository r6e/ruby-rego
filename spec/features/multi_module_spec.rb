# frozen_string_literal: true

require "spec_helper"

# rubocop:disable Metrics/BlockLength
RSpec.describe "Multi-module evaluation" do
  def evaluate(modules, query:, input: {}, data: {})
    set = Ruby::Rego::Compiler.new.compile_set(modules)
    Ruby::Rego::Evaluator.for_policy_set(set, input: input, data: data).evaluate(query)
  end

  it "resolves a cross-package reference" do
    result = evaluate(
      {
        "authz.rego" => <<~REGO,
          package acme.authz
          allow if data.acme.users.is_admin
        REGO
        "users.rego" => <<~REGO
          package acme.users
          is_admin if input.user == "root"
        REGO
      },
      query: "data.acme.authz.allow",
      input: { "user" => "root" }
    )

    expect(result.value.to_ruby).to be(true)
  end

  it "returns nested results keyed by package for the no-query path" do
    set = Ruby::Rego::Compiler.new.compile_set(
      "a.rego" => "package a\nfoo := 1\n",
      "b.rego" => "package b\nbar := 2\n"
    )
    result = Ruby::Rego::Evaluator.for_policy_set(set, input: {}, data: {}).evaluate

    expect(result.value.to_ruby).to eq(
      "a" => { "foo" => 1 },
      "b" => { "bar" => 2 }
    )
  end

  it "evaluates a merged same-package set" do
    result = evaluate(
      {
        "one.rego" => "package shared\nfoo := 1\n",
        "two.rego" => "package shared\nbar := foo + 1\n"
      },
      query: "data.shared.bar"
    )

    expect(result.value.to_ruby).to eq(2)
  end
end
# rubocop:enable Metrics/BlockLength
