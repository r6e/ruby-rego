# Examples

## CLI validation example

From the repository root:

```bash
bundle exec exe/rego-validate --policy examples/validation_policy.rego --config examples/sample_config.yaml
```

Override the default query:

```bash
bundle exec exe/rego-validate --policy examples/validation_policy.rego --config examples/sample_config.yaml --query data.validation.deny
```

## Ruby API example

```ruby
require "ruby/rego"

policy = File.read("examples/simple_policy.rego")
input = {"user" => "admin"}

result = Ruby::Rego.evaluate(policy, input: input, query: "data.example.allow")
puts result.value.to_ruby
```
