# frozen_string_literal: true

require "spec_helper"

OBJECT_BUILTINS_POLICY = <<~REGO
  package objects

  merged := object.union(input.base, input.override)

  combined := object.union_n(input.layers)

  public := object.filter(input.record, input.allowed)
REGO

RSpec.describe "object builtins (integration)" do
  def evaluate(rule, input)
    Ruby::Rego.evaluate(OBJECT_BUILTINS_POLICY, input: input, query: "data.objects.#{rule}")
  end

  it "deep-merges two objects from input" do
    result = evaluate("merged", {
                        "base" => { "a" => 1, "nested" => { "x" => 1 } },
                        "override" => { "nested" => { "y" => 2 }, "b" => 3 }
                      })
    expect(result.value.to_ruby).to eq("a" => 1, "nested" => { "x" => 1, "y" => 2 }, "b" => 3)
  end

  it "folds a union across a layer list" do
    result = evaluate("combined", { "layers" => [{ "a" => 1 }, { "b" => 2 }, { "a" => 9 }] })
    expect(result.value.to_ruby).to eq("a" => 9, "b" => 2)
  end

  it "filters an object down to allowed keys" do
    result = evaluate("public", {
                        "record" => { "name" => "x", "ssn" => "secret", "email" => "e" },
                        "allowed" => %w[name email]
                      })
    expect(result.value.to_ruby).to eq("name" => "x", "email" => "e")
  end
end
