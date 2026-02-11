# frozen_string_literal: true

require "benchmark/ips"
require "ruby/rego"

policy = <<~REGO
  package bench
  result {
    count(input.items) == 100
    sum(input.numbers) > 2000
    max(input.numbers) == 200
    startswith(input.name, "user")
    lower(input.name) == "user-1"
  }
REGO

compiled = Ruby::Rego.compile(policy)
input = {
  "items" => Array.new(100, "item"),
  "numbers" => (1..200).to_a,
  "name" => "User-1"
}
query = "data.bench.result"
evaluator = Ruby::Rego::Evaluator.new(compiled, input: input)

Benchmark.ips do |x|
  x.report("builtin calls") { evaluator.evaluate(query) }
  x.compare!
end
