# frozen_string_literal: true

require "spec_helper"

# time.now_ns is impure: like OPA, the clock is fixed ONCE per evaluation — every call within a
# single query returns the same nanosecond timestamp, but a fresh evaluate() reads the clock
# again. These behaviours are only observable through the real front door (Ruby::Rego.evaluate),
# since the per-eval clock is injected as a registry overlay during evaluation.
TIME_NOW_POLICY = <<~REGO
  package now

  pair := [time.now_ns(), time.now_ns()]

  single := time.now_ns()

  overridden := y if { y := time.now_ns() with time.now_ns as 1234567890 }

  is_int if is_number(time.now_ns())
REGO

# rubocop:disable Metrics/BlockLength
RSpec.describe "time.now_ns (integration)" do
  def evaluate(rule)
    Ruby::Rego.evaluate(TIME_NOW_POLICY, query: "data.now.#{rule}").value.to_ruby
  end

  def current_ns
    (Time.now.to_r * 1_000_000_000).to_i
  end

  it "returns the same value for every call within a single evaluation" do
    first, second = evaluate("pair")
    expect(first).to eq(second)
  end

  it "reads the wall clock fresh on each evaluation (within the eval's time window)" do
    before = current_ns
    result = evaluate("single")
    after = current_ns
    # The eval's fixed clock must fall within the wall-clock window around the call — proving it
    # reads Time.now at eval time (in nanoseconds), not a stale or wrong-unit value. minmax keeps
    # the window valid even if the wall clock steps backward between the reads (e.g. an NTP adjust).
    low, high = [before, after].minmax
    expect(result).to be_between(low, high)
  end

  it "returns an integer (number) value" do
    expect(evaluate("is_int")).to be(true)
  end

  it "is overridable via `with time.now_ns as <value>`" do
    expect(evaluate("overridden")).to eq(1_234_567_890)
  end

  it "fixes the clock once across all modules of a policy set" do
    # The overlay lives on the environment shared by every module, so a call in one module and
    # another in a different module within the same evaluation see the same timestamp.
    modules = {
      "a.rego" => "package a\nimport data.b\npair := [b.first, b.second]",
      "b.rego" => "package b\nfirst := time.now_ns()\nsecond := time.now_ns()"
    }
    first, second = Ruby::Rego.evaluate_modules(modules, query: "data.a.pair").value.to_ruby
    expect(first).to eq(second)
  end
end
# rubocop:enable Metrics/BlockLength
