# frozen_string_literal: true

require "benchmark/ips"
require "ruby/rego"

policy = <<~REGO
  package bench
  evens := [n | some n in input.numbers; n % 2 == 0]
REGO

compiled = Ruby::Rego.compile(policy)
input = { "numbers" => (1..200).to_a }
query = "data.bench.evens"
evaluator = Ruby::Rego::Evaluator.new(compiled, input: input)

Benchmark.ips do |x|
  x.report("comprehension") { evaluator.evaluate(query) }
  x.compare!
end
