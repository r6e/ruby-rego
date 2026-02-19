# Ruby::Rego

Ruby::Rego is a pure Ruby implementation of the Open Policy Agent (OPA) Rego policy language. The project targets a clean, Ruby-idiomatic API with strong test coverage and type signatures while working toward broader Rego compatibility.

## Project goals

- Provide a stable Ruby API for parsing, compiling, and evaluating Rego policies.
- Offer a deterministic evaluator with clear error reporting.
- Keep compiled modules immutable and safe to reuse.
- Ship a CLI for common validation workflows.

## Status

The gem is under active development and does not yet cover the full OPA specification. Please review the supported feature list below before relying on it in production.

## Installation

Install the gem and add it to your Gemfile:

```bash
bundle add ruby-rego
```

If you are not using Bundler, install it directly:

```bash
gem install ruby-rego
```

## Quick start

```ruby
require "ruby/rego"

policy = <<~REGO
  package example
  default allow = false
  allow { input.user == "admin" }
REGO

result = Ruby::Rego.evaluate(policy, input: {"user" => "admin"}, query: "data.example.allow")
puts result.value.to_ruby
```

## API documentation

### Basic parsing

```ruby
require "ruby/rego"

tokens = Ruby::Rego::Lexer.new(policy).tokenize
ast_module = Ruby::Rego::Parser.new(tokens).parse
```

### Policy evaluation

```ruby
require "ruby/rego"

compiled = Ruby::Rego.compile(policy)
evaluator = Ruby::Rego::Evaluator.new(compiled, input: {"user" => "admin"})
result = evaluator.evaluate("data.example.allow")
puts result.to_h
```

### Validation use case

```ruby
require "ruby/rego"
require "yaml"

policy_source = File.read("examples/validation_policy.rego")
config_hash = YAML.safe_load(File.read("examples/sample_config.yaml"))

policy = Ruby::Rego::Policy.new(policy_source)
result = policy.evaluate(input: config_hash, query: "data.validation.deny")

if result.undefined?
  puts "No decision"
elsif result.success?
  puts "OK"
else
  puts "Errors: #{result.value.to_ruby.inspect}"
end
```

### CLI usage

```bash
bundle exec exe/rego-validate --policy examples/validation_policy.rego --config examples/sample_config.yaml
```

The CLI attempts to infer a validation query in this order: `deny`, `violations`, `violation`, `errors`, `error`, then falls back to `allow`. You can override this with `--query`.

## Supported Rego features

### Language support

- Packages and imports.
- Rule definitions (complete and partial rules, defaults, else).
- Literals and references, including input/data.
- Collections: arrays, objects, sets.
- Comprehensions (array, object, set).
- Operators: assignment, unification, comparisons, arithmetic, and boolean logic.
- Keywords: `some`, `not`, `every` (experimental), and `with` (limited).

### Built-in functions

Built-ins are currently limited to core categories: types, aggregates, strings, collections, and comparisons. See the builtins registry for the current list.

### Known limitations

- Not full OPA spec coverage yet.
- Advanced `with` semantics, partial evaluation, and additional built-ins are still in progress.
- Performance work is ongoing; expect lower throughput than OPA.

## Performance and benchmarks

Ruby::Rego focuses on correctness and clarity over raw throughput. Expect performance to scale with
policy complexity: deep references, large comprehensions, and heavy use of `with` modifiers cost more.
Memoization caches rule outputs and static references during a single evaluation to reduce repeated work.

### Comparison with OPA

OPA (Go) is highly optimized and typically faster, especially on large policies or high-throughput workloads.
Use Ruby::Rego when you need a pure Ruby runtime or tight integration with Ruby applications, and prefer OPA
for latency-critical or batch-heavy policy evaluation.

### Tips for performant policies

- Prefer indexed data structures and avoid deep, repeated reference chains.
- Keep comprehensions small; filter early and avoid nested comprehensions when possible.
- Use built-ins like `count`, `sum`, and `object.get` instead of manual loops.
- Avoid `with` modifiers on hot paths; they are intentionally isolated and reset memoization caches.
- Keep rule dependencies shallow to minimize repeated rule evaluation.

### Running benchmarks

Benchmarks use `benchmark-ips` and live in the `benchmark/` directory:

```bash
bundle exec ruby benchmark/simple_rules.rb
bundle exec ruby benchmark/comprehensions.rb
bundle exec ruby benchmark/builtin_calls.rb
bundle exec ruby benchmark/complex_policy.rb
```

### CLI profiling

Use `--profile` to capture timing and memory deltas for compilation and evaluation. Profiling output is
emitted to stderr so JSON output remains machine-readable.

```bash
bundle exec exe/rego-validate --policy examples/validation_policy.rego --config examples/sample_config.yaml --profile
```

## Contributing

Bug reports and pull requests are welcome on GitHub at [https://github.com/r6e/ruby-rego](https://github.com/r6e/ruby-rego).

1. Run `bin/setup` to install dependencies.
2. Run tests with `bundle exec rspec`.
3. Run quality checks:

```bash
bundle exec rubocop
bundle exec reek lib/
bundle exec rubycritic lib/
bundle exec steep check
bundle exec bundler-audit check --update
```

Please include tests and documentation updates with your changes.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Ruby::Rego project is expected to follow the code of conduct.
