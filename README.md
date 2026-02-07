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
bundle exec typeprof lib/**/*.rb
bundle exec bundler-audit check --update
```

Please include tests and documentation updates with your changes.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Ruby::Rego project is expected to follow the code of conduct.
