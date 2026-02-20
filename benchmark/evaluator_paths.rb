# frozen_string_literal: true

require "benchmark/ips"
require "ruby/rego"

def evaluator_for(policy, query:, input: {})
  compiled = Ruby::Rego.compile(policy)
  evaluator = Ruby::Rego::Evaluator.new(compiled, input: input)

  [evaluator, query]
end

baseline_policy = <<~REGO
  package bench_baseline

  default allow = false

  allow if input.user == "admin"
REGO

every_policy = <<~REGO
  package bench_every

  allow if {
    every x in input.values { x > 0 }
  }
REGO

head_ref_policy = <<~REGO
  package bench_head_ref

  fruit[input.color].shade := "bright" if input.color
  fruit[input.color].size := input.size if input.color
REGO

destructuring_policy = <<~REGO
  package bench_destructuring

  allow if {
    {"profile": {"tier": tier}, "roles": roles} := input.user
    [primary_role, _] := roles
    startswith(primary_role, "eng")
    tier >= 2
  }
REGO

builtin_policy = <<~REGO
  package bench_builtins

  allow if {
    startswith(input.path, "/api")
    count(input.values) == 3
  }
REGO

with_policy = <<~REGO
  package bench_with

  allow if count(input.values) == 6 with count as sum
REGO

with_baseline_policy = <<~REGO
  package bench_with_baseline

  allow if count(input.values) == 3
REGO

combined_policy = <<~REGO
  package bench_combined

  user_checks[name].valid := true if {
    some name, user in input.users
    {"profile": {"tier": tier}, "roles": roles} := user
    [primary_role, _] := roles
    startswith(primary_role, "eng")
    count(roles) >= 2
    every required in input.required_roles { required in roles }
    tier >= 2
  }

  simulated_valid[name] if {
    some name, _ in input.simulated.users
    user_checks[name].valid with input.required_roles as input.simulated.required_roles with input.users as input.simulated.users
  }
REGO

baseline_eval, baseline_query = evaluator_for(
  baseline_policy,
  input: { "user" => "admin" },
  query: "data.bench_baseline.allow"
)

every_eval, every_query = evaluator_for(
  every_policy,
  input: { "values" => [1, 2, 3, 4, 5] },
  query: "data.bench_every.allow"
)

head_ref_eval, head_ref_query = evaluator_for(
  head_ref_policy,
  input: { "color" => "red", "size" => 3 },
  query: "data.bench_head_ref.fruit"
)

destructuring_eval, destructuring_query = evaluator_for(
  destructuring_policy,
  input: {
    "user" => {
      "roles" => %w[eng_admin audit],
      "profile" => { "tier" => 3 }
    }
  },
  query: "data.bench_destructuring.allow"
)

builtin_eval, builtin_query = evaluator_for(
  builtin_policy,
  input: {
    "path" => "/api/v1",
    "values" => [1, 2, 3]
  },
  query: "data.bench_builtins.allow"
)

with_eval, with_query = evaluator_for(
  with_policy,
  input: { "values" => [1, 2, 3] },
  query: "data.bench_with.allow"
)

with_baseline_eval, with_baseline_query = evaluator_for(
  with_baseline_policy,
  input: { "values" => [1, 2, 3] },
  query: "data.bench_with_baseline.allow"
)

combined_eval, combined_query = evaluator_for(
  combined_policy,
  input: {
    "users" => {
      "alice" => {
        "roles" => %w[eng_admin audit],
        "profile" => { "tier" => 3 }
      },
      "bob" => {
        "roles" => %w[eng_viewer],
        "profile" => { "tier" => 3 }
      }
    },
    "required_roles" => %w[eng_admin audit],
    "simulated" => {
      "required_roles" => %w[eng_viewer],
      "users" => {
        "alice" => {
          "roles" => %w[eng_admin audit],
          "profile" => { "tier" => 3 }
        },
        "bob" => {
          "roles" => %w[eng_viewer ops],
          "profile" => { "tier" => 3 }
        }
      }
    }
  },
  query: "data.bench_combined.simulated_valid"
)

Benchmark.ips do |x|
  x.config(time: 2, warmup: 1)

  x.report("baseline simple rule") { baseline_eval.evaluate(baseline_query) }
  x.report("every quantifier") { every_eval.evaluate(every_query) }
  x.report("rule-head references") { head_ref_eval.evaluate(head_ref_query) }
  x.report("destructuring") { destructuring_eval.evaluate(destructuring_query) }
  x.report("built-ins") { builtin_eval.evaluate(builtin_query) }
  x.report("no with (count)") { with_baseline_eval.evaluate(with_baseline_query) }
  x.report("with override") { with_eval.evaluate(with_query) }
  x.report("combined path") { combined_eval.evaluate(combined_query) }

  x.compare!
end
