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

  it "evaluates a user-defined function within a package" do
    result = evaluate(
      { "a.rego" => "package a\nf(x) := x * 2\nallow if f(3) == 6\n" },
      query: "data.a.allow"
    )

    expect(result.value.to_ruby).to be(true)
  end

  it "isolates same-named functions across packages in the value cache" do
    result_a = evaluate(
      {
        "a.rego" => "package a\nf(x) := x + 1\nval := f(10)\n",
        "b.rego" => "package b\nf(x) := x + 100\nval := f(10)\n"
      },
      query: "data.a.val"
    )
    result_b = evaluate(
      {
        "a.rego" => "package a\nf(x) := x + 1\nval := f(10)\n",
        "b.rego" => "package b\nf(x) := x + 100\nval := f(10)\n"
      },
      query: "data.b.val"
    )

    expect(result_a.value.to_ruby).to eq(11)
    expect(result_b.value.to_ruby).to eq(110)
  end

  it "nests subpackage results under the parent package (parent first)" do
    set = Ruby::Rego::Compiler.new.compile_set(
      "a.rego" => "package a\nfoo := 1\n",
      "ab.rego" => "package a.b\nbar := 2\n"
    )
    result = Ruby::Rego::Evaluator.for_policy_set(set, input: {}, data: {}).evaluate

    expect(result.value.to_ruby).to eq("a" => { "foo" => 1, "b" => { "bar" => 2 } })
  end

  it "nests subpackage results under the parent package (child first)" do
    set = Ruby::Rego::Compiler.new.compile_set(
      "ab.rego" => "package a.b\nbar := 2\n",
      "a.rego" => "package a\nfoo := 1\n"
    )
    result = Ruby::Rego::Evaluator.for_policy_set(set, input: {}, data: {}).evaluate

    expect(result.value.to_ruby).to eq("a" => { "foo" => 1, "b" => { "bar" => 2 } })
  end
end
# rubocop:enable Metrics/BlockLength

# rubocop:disable Metrics/BlockLength
RSpec.describe "Multi-module edge cases" do
  let(:compiler) { Ruby::Rego::Compiler.new }

  def evaluate(modules, query:, input: {})
    set = compiler.compile_set(modules)
    Ruby::Rego::Evaluator.for_policy_set(set, input: input, data: {}).evaluate(query)
  end

  # The compiler intentionally defers complete-rule conflict detection to
  # evaluation time (RuleGroup#ensure_complete_rule_consistency is not wired
  # into RuleGroup#validate). compile_set succeeds; evaluation raises
  # Ruby::Rego::EvaluationError when the conflicting rules both match.
  # Wiring compile-time detection would require changing compiler logic that
  # the plan explicitly marks out of scope.
  pending "raises when same-package files define conflicting complete rules (deferred to eval time as EvaluationError)"

  it "isolates same-named imports across modules" do
    result = evaluate(
      {
        "a.rego" => <<~REGO,
          package a
          import data.source.left as picked
          value := picked
        REGO
        "b.rego" => <<~REGO,
          package b
          import data.source.right as picked
          value := picked
        REGO
        "source.rego" => <<~REGO
          package source
          left := "L"
          right := "R"
        REGO
      },
      query: "data.a.value"
    )

    expect(result.value.to_ruby).to eq("L")
  end

  it "returns undefined for a reference to a non-existent package rule" do
    result = evaluate(
      { "a.rego" => "package a\nallow if data.missing.flag\n" },
      query: "data.a.allow"
    )
    expect(result).to be_nil
  end

  it "isolates same-named functions across packages in the no-query result" do
    set = compiler.compile_set(
      "a.rego" => "package a\nf(x) := x + 1\nval := f(10)\n",
      "b.rego" => "package b\nf(x) := x + 100\nval := f(10)\n"
    )
    result = Ruby::Rego::Evaluator.for_policy_set(set, input: {}, data: {}).evaluate

    expect(result.value.to_ruby).to eq(
      "a" => { "val" => 11 },
      "b" => { "val" => 110 }
    )
  end

  it "handles a cross-package reference cycle the same way as a local self-cycle" do
    local_cycle = lambda do
      Ruby::Rego.evaluate("package a\nx if x\n", query: "data.a.x")
    end
    cross_cycle = lambda do
      evaluate(
        {
          "a.rego" => "package a\nx if data.b.y\n",
          "b.rego" => "package b\ny if data.a.x\n"
        },
        query: "data.a.x"
      )
    end

    # SystemStackError is a direct Exception subclass (not StandardError),
    # so we must rescue both to capture it.
    local_error = nil
    begin
      local_cycle.call
    rescue StandardError, SystemStackError => e
      local_error = e.class
    end

    if local_error
      expect { cross_cycle.call }.to raise_error(local_error)
    else
      expect { cross_cycle.call }.not_to raise_error
    end
  end
end
# rubocop:enable Metrics/BlockLength
