# frozen_string_literal: true

require "spec_helper"

# uuid.rfc4122(key) is impure: like OPA it returns a random RFC 4122 version-4 UUID, MEMOIZED by
# the key within a single evaluation (same key → same UUID; different keys → different), while a
# fresh evaluate() generates fresh UUIDs. The per-eval memo is supplied by an evaluator overlay,
# so these behaviours are only observable through the real front door (Ruby::Rego.evaluate).
UUID_RFC4122_POLICY = <<~REGO
  package u

  single := uuid.rfc4122("k")
  pair := [uuid.rfc4122("k"), uuid.rfc4122("k")]
  distinct := uuid.rfc4122("a") != uuid.rfc4122("b")

  first := uuid.rfc4122("same")
  second := uuid.rfc4122("same")
  cross_rule := first == second

  num_pair := [uuid.rfc4122(42), uuid.rfc4122(42)]
  typed_distinct := uuid.rfc4122(42) != uuid.rfc4122("42")

  overridden := y if { y := uuid.rfc4122("k") with uuid.rfc4122 as "fixed-uuid" }
REGO

# 8-4-4-4-12 hex with the version nibble fixed at 4 and the variant nibble in [8,b] (RFC 4122 v4).
UUID_V4 = /\A\h{8}-\h{4}-4\h{3}-[89ab]\h{3}-\h{12}\z/

# rubocop:disable Metrics/BlockLength
RSpec.describe "uuid.rfc4122 (integration)" do
  def evaluate(rule)
    Ruby::Rego.evaluate(UUID_RFC4122_POLICY, query: "data.u.#{rule}").value.to_ruby
  end

  it "returns a valid RFC 4122 version-4 UUID" do
    expect(evaluate("single")).to match(UUID_V4)
  end

  it "memoizes by key within one evaluation (same key → same UUID)" do
    first, second = evaluate("pair")
    expect(first).to eq(second)
  end

  it "returns different UUIDs for different keys" do
    expect(evaluate("distinct")).to be(true)
  end

  it "shares the memo across rules within one evaluation" do
    expect(evaluate("cross_rule")).to be(true)
  end

  it "generates fresh UUIDs on a separate evaluation" do
    # Collision probability is ~2^-122; the value is fresh per evaluate().
    expect(evaluate("single")).not_to eq(evaluate("single"))
  end

  it "accepts a non-string key at runtime and memoizes it by value" do
    first, second = evaluate("num_pair")
    expect(first).to match(UUID_V4)
    expect(first).to eq(second)
  end

  it "treats values of different types as distinct keys (42 vs \"42\")" do
    expect(evaluate("typed_distinct")).to be(true)
  end

  it "is overridable via `with uuid.rfc4122 as <value>`" do
    expect(evaluate("overridden")).to eq("fixed-uuid")
  end

  it "coexists with time.now_ns in one evaluation (both impure overrides in the shared overlay)" do
    # The per-eval overlay installs both time.now_ns and uuid.rfc4122; confirm both are fixed
    # within the same evaluation and that unrelated builtins still fall through to the base.
    policy = <<~REGO
      package both
      result := {
        "now_consistent": time.now_ns() == time.now_ns(),
        "uuid_consistent": uuid.rfc4122("k") == uuid.rfc4122("k"),
        "uuid_valid": regex.match(`^\\h{8}-\\h{4}-4\\h{3}-[89ab]\\h{3}-\\h{12}$`, uuid.rfc4122("k")),
        "base_builtin": upper("hi"),
      }
    REGO
    result = Ruby::Rego.evaluate(policy, query: "data.both.result").value.to_ruby
    expect(result).to eq("now_consistent" => true, "uuid_consistent" => true,
                         "uuid_valid" => true, "base_builtin" => "HI")
  end
end
# rubocop:enable Metrics/BlockLength
