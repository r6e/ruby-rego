# Ruby::Rego

Pure Ruby implementation of the Open Policy Agent (OPA) Rego policy language.

This gem is in early development. The initial focus is a clean, Ruby-idiomatic API, comprehensive type signatures, and strong test coverage.

## Installation

Install the gem and add to the application's Gemfile by executing:

```bash
bundle add ruby-rego
```

If bundler is not being used to manage dependencies, install the gem by executing:

```bash
gem install ruby-rego
```

## Usage

The public API is under active development. The planned interface will provide high-level helpers to parse and evaluate Rego policies.

```ruby
require "ruby/rego"

policy = <<~REGO
  package example
  default allow = false
  allow { input.user == "admin" }
REGO

result = Ruby::Rego.evaluate(policy, input: {"user" => "admin"}, query: "data.example.allow")
puts result
```

Low-level API (current):

```ruby
tokens = Ruby::Rego::Lexer.new(policy).tokenize
ast_module = Ruby::Rego::Parser.new(tokens).parse
evaluator = Ruby::Rego::Evaluator.from_ast(ast_module, input: {"user" => "admin"})
result = evaluator.evaluate
```

Compiled modules are immutable; rule tables and dependency graphs are frozen for safe reuse.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

Quality and type-checking tasks:

```bash
bundle exec rake rubocop
bundle exec rake reek
bundle exec rake rubycritic
bundle exec rake steep
bundle exec rake typeprof
bundle exec rake bundler_audit
```

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/r6e/ruby-rego. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Ruby::Rego project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the code of conduct.
