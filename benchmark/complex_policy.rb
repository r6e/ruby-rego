# frozen_string_literal: true

require "benchmark/ips"
require "yaml"
require "ruby/rego"

policy_path = File.join(__dir__, "..", "examples", "validation_policy.rego")
config_path = File.join(__dir__, "..", "examples", "sample_config.yaml")

policy = File.read(policy_path)
input = YAML.safe_load_file(config_path)
compiled = Ruby::Rego.compile(policy)
query = "data.validation.deny"
evaluator = Ruby::Rego::Evaluator.new(compiled, input: input)

Benchmark.ips do |x|
  x.report("complex policy") { evaluator.evaluate(query) }
  x.compare!
end
