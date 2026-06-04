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

if result.nil?
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

Built-ins are currently limited to core categories: types, aggregates, numbers (`abs`, `round`, `ceil`, `floor`, `numbers.range`), bits (`bits.and`/`or`/`xor`/`negate`/`lsh`/`rsh`), glob (`glob.match`, `glob.quote_meta`), regex (`regex.match`, `regex.is_valid`, `regex.split`, `regex.find_n`, `regex.replace`), encoding (`json.marshal`, `json.unmarshal`, `json.is_valid`, `base64` encode/decode/is_valid, `base64url` encode/decode/`encode_no_pad`, `hex` encode/decode, `urlquery` encode/decode/`encode_object`/`decode_object`), strings (including `replace`, `strings.replace_n`, `trim_prefix`/`trim_suffix`, `strings.reverse`/`count`, `indexof_n`, `strings.any_prefix_match`/`any_suffix_match`), collections (including `object.get`/`keys`/`remove`/`union`/`union_n`/`filter`), crypto (`crypto.md5`/`sha1`/`sha256`, `crypto.hmac.md5`/`sha1`/`sha256`/`sha512`, `crypto.hmac.equal`), net (`net.cidr_contains`, `net.cidr_intersects`, `net.cidr_is_valid`), semver (`semver.is_valid`, `semver.compare`), and comparisons. See the builtins registry for the current list.

The `semver.*` built-ins match OPA's Semantic Versioning behavior (`MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]`): the parser is lenient like OPA's — it accepts a leading lowercase `v` and leading zeros in numeric components — and each numeric component must fit in a signed 64-bit integer. `semver.is_valid` is total over runtime values (a non-string yields `false`); `semver.compare(a, b)` returns `-1`/`0`/`1` and yields undefined for a non-string or invalid version (build metadata is ignored; precedence follows SemVer §11). One intentional divergence: OPA's `semver.compare` infinite-loops when two numeric prerelease identifiers are equal in value but differ textually via leading zeros (e.g. `1.0.0-01` vs `1.0.0-1`) — an upstream coreos/go-semver bug. This implementation compares them numerically (equal), terminates, and returns the correct result rather than hanging.

The `net.cidr_*` built-ins are backed by Ruby's `IPAddr` and support IPv4 and IPv6. A "cidr" requires a prefix length (`10.0.0.0/8`, not a bare IP); host bits beyond the prefix are masked. `net.cidr_contains(cidr, ip_or_cidr)` and `net.cidr_intersects(cidr, cidr)` return a boolean and yield undefined for a non-string or invalid argument (and `false` across address families). `net.cidr_is_valid` is total over runtime values — a non-string or non-CIDR string yields `false` (not undefined). Parsing matches OPA's strictness: a dotted-decimal netmask (`/255.0.0.0`), a scoped (`%zone`) or bracketed (`[::1]`) address is rejected, while a leading-zero prefix (`/08`) is accepted as `/8`. IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are treated as their native IPv4 form, matching OPA. The one intentional divergence: an IPv4-mapped IPv6 CIDR whose prefix is in `80..95` (cutting through the `::ffff:` marker) is a degenerate input where OPA inherits [golang/go#51906](https://github.com/golang/go/issues/51906) and `net.cidr_contains` becomes non-reflexive; the gem keeps the reflexive result (a network contains itself) rather than reproduce the upstream Go inconsistency.

The `crypto.hmac.*` digests take `(message, key)` (OPA's order) and return a lowercase hex HMAC; `crypto.hmac.equal(mac1, mac2)` is a constant-time comparison returning a boolean (`false` for unequal-length inputs). A non-string argument to any crypto built-in yields undefined.

Regex built-ins compile patterns with Ruby's regex engine (Onigmo), not Go's RE2. Common patterns behave identically to OPA; constructs Ruby accepts but RE2 rejects (lookahead, backreferences) are treated as valid here, so `regex.is_valid` reflects Ruby's notion of validity. `regex.is_valid` is total over runtime values like OPA's: a non-string argument yields `false` (not undefined, unlike the other regex built-ins), and an over-length pattern yields `false` (anti-DoS, see below; OPA reports a large valid pattern `true`). Two engine differences are silent divergences affecting every regex built-in (`regex.match`, `regex.find_n`, `regex.split`, `regex.replace`): the `^` and `$` anchors are line anchors in Onigmo but text anchors in RE2, so on a multi-line subject (one containing `\n`) they match at every line boundary in the gem but only once at the string ends in OPA; and the `\b`/`\w`/`\d`/`\s` shorthand classes are Unicode-aware in Onigmo but ASCII-only in RE2, so they match non-ASCII word characters in the gem but not in OPA. Go's `(?P<name>...)` named-group syntax — and RE2's `(?<name>...)` synonym for it — are supported: named groups are rewritten to plain capturing groups and `${name}` references resolve through a name→index map, so named and unnamed groups share one left-to-right numbering space exactly as in RE2 (mixing `(?P<x>...)`/`(?<x>...)` with `(...)` and numbered references works). Group names must be RE2 identifiers (`[A-Za-z0-9_]+`) for `${name}` resolution. A non-identifier (e.g. Unicode) name is rejected in the `(?P<…>` form, matching RE2 (→ undefined, since Onigmo has no `(?P<` syntax); but the `(?<…>` form is Onigmo-native, so such a name is accepted and matched per the superset policy above, where OPA is undefined — the two synonyms therefore diverge for non-identifier names. `${name}` resolution is guaranteed only for these two RE2 syntaxes; the Ruby-only `(?'name'…)` form likewise follows the superset policy (OPA rejects it). `regex.replace` expands Go's `Expand` template syntax in the replacement value (`$1`, `${name}`, `$0` for the whole match, `$$` for a literal `$`; an unknown or out-of-range reference, including a multi-digit leading-zero one like `$01`, expands to the empty string), not Ruby's `\1` syntax. As anti-DoS guards, every regex built-in yields undefined rather than exhausting resources: a pattern or replacement template longer than ~1M bytes is rejected up front (it is otherwise split into a character array — an uninterruptible operation no timeout can bound); the configurable timeout (`RUBY_REGO_REGEX_TIMEOUT`, default 1s) bounds a single match (catastrophic backtracking) and, as an aggregate deadline, the whole match loop (a pattern cheap per match but scanning the subject on each of O(n) matches would otherwise be quadratic); additionally `regex.replace` caps its expanded output (~32M characters) and its total template-segment expansions (matches × template segments, ~32M — which bounds CPU even when references resolve to empty and emit nothing). These bounds are deliberate divergences from OPA; like OPA's own evaluation limits, they make a sufficiently large-or-pathological input undefined rather than a hang.

### Multi-module composition

`Ruby::Rego.compile_modules` and `Ruby::Rego.evaluate_modules` compile and evaluate a named set of Rego modules that reference each other across packages. Multiple files declaring the same package are merged OPA-style (rules and imports are unioned; identical shared imports are de-duplicated). Per-module import scoping is preserved.

```ruby
require "ruby/rego"

modules = {
  "authz.rego" => <<~REGO,
    package acme.authz
    allow if data.acme.users.is_admin
  REGO
  "users.rego" => <<~REGO
    package acme.users
    is_admin if input.user == "root"
  REGO
}

result = Ruby::Rego.evaluate_modules(modules, input: {"user" => "root"}, query: "data.acme.authz.allow")
puts result.value.to_ruby  # => true
```

The CLI remains single-file only.

### Known limitations

- Not full OPA spec coverage yet.
- No non-standard destructuring extensions (e.g., rest elements or partial-object remainder capture).
- Advanced `with` semantics, partial evaluation, and additional built-ins are still in progress.
- Performance work is ongoing; expect lower throughput than OPA.
- Cross-package function calls are not supported (e.g., calling `data.a.f(x)` from another package); within-package calls work normally.
- No cross-module cycle detection: a cyclic reference across packages will stack-overflow rather than fail at compile time.
- Querying a bare package path (e.g., `query: "data.acme.authz"`) does not return the package's aggregated document; query a specific rule path instead.
- Conflicting complete rules within a merged package surface as an evaluation-time error, not a compile-time error.
- `strings.replace_n` scans by Unicode codepoint rather than byte. This differs from OPA only for an empty (`""`) key applied to multibyte text: OPA (byte-based) inserts the replacement between a character's bytes and yields invalid UTF-8, while this implementation inserts only at codepoint boundaries to keep output valid. All non-empty keys behave identically to OPA.
- `bits.lsh` yields undefined when the result would exceed 2^25 bits (~4 MB), a DoS guard against unbounded allocation from an untrusted shift amount. OPA computes arbitrarily large shifts (slowly); this is the only divergence and affects only left shifts.
- Reference segments after a dot may use the keywords `and`/`or` (e.g. `bits.and`), in addition to `data`/`input`. OPA permits any keyword as a dotted segment; the other keywords (`if`, `every`, `in`, `with`, etc.) are not yet accepted in that position here.
- `glob.match` implements correct glob semantics rather than reproducing known bugs in OPA's matcher (gobwas/glob). Unlike OPA: character classes use standard semantics — multiple ranges and ranges mixed with literals, such as `[A-Za-z]` and `[a0-9]` — rather than gobwas's restrictive single-range grammar ([gobwas #47](https://github.com/gobwas/glob/issues/47)); `?` matches non-ASCII characters consistently by Unicode codepoint, including mid-pattern where OPA's `?` still fails on non-ASCII ([gobwas #41](https://github.com/gobwas/glob/issues/41)); and `?`/`[!...]` require exactly one character instead of also matching the empty string; and the gem yields undefined for degenerate forms OPA leniently accepts (an unterminated `{a,b`, an empty `{}`, and a trailing or lone backslash). Other malformed patterns (unclosed class, reversed range) yield undefined consistent with OPA. Outside these corrections, well-formed patterns behave identically to OPA. To stay bounded on untrusted input, patterns with more than 65,536 delimiters, brace nesting deeper than 100, or a compiled regex source over 1 MB yield undefined (DoS guards).

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
