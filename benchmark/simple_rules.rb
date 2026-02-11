# frozen_string_literal: true

require "benchmark/ips"
require "ruby/rego"

policy = <<~REGO
  package bench
  default allow = false
  allow { input.user == "admin" }
REGO

compiled = Ruby::Rego.compile(policy)
input = { "user" => "admin" }
query = "data.bench.allow"
evaluator = Ruby::Rego::Evaluator.new(compiled, input: input)

Benchmark.ips do |x|
  x.report("simple rule") { evaluator.evaluate(query) }
  x.compare!
end
