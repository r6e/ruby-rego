# TODO

This roadmap is graded against the project's own definition of "feature-complete"
(the phases below), with full OPA as the external comparison point. The README
explicitly disclaims full-OPA-spec coverage, so OPA's ~210 builtins are a reference
target, not the bar for each phase.

Status legend: ✅ done · 🟡 partial · ⬜ not started

## Current state (v0.1.0)

The **core language engine is largely complete**: lexer, parser, AST, compiler,
and evaluator cover packages, imports (aliases + shadowing), complete and partial
rules, `default`, `else`, user-defined functions, Rego v1 sugar (`if`/`contains`),
all operators (equality, logical, comparison, arithmetic, membership), the `some`,
`not`, `with`, and `every` keywords, and array/object/set comprehensions. 392 specs
pass at ~94% line coverage.

What remains is split between **additive** work (more builtins — low risk, high
volume) and **architectural** work (multi-module composition, partial evaluation,
annotations — these ripple structurally and are not "just more functions").

## Phase 2 features

- ✅ Full `every` keyword semantics and test coverage.
- ✅ Rule heads with references (indexing and evaluation).
- 🟡 OPA-compatible pattern matching and destructuring hardening in rule bodies
  (no non-standard rest/partial-object extensions).
- 🟡 Broader `with` keyword support across evaluator paths.
- 🟡 Expanded built-in function set (see "Built-in function backlog" below).
- ✅ **Multi-module composition (top priority).** Today `compile(source)` takes a
  single source string and produces one `CompiledModule` with one package path;
  the evaluator consumes exactly one module. Real OPA usage composes many `.rego`
  files into a single `data` namespace where one package references another
  (`data.b.allow`). This is the largest functional ceiling and is currently
  impossible. Scope:
  - Public API: accept multiple sources/modules in `compile`/`evaluate`.
  - Compiler: merge modules, detect package/rule conflicts, build a cross-module
    dependency graph.
  - Evaluator/reference resolution: resolve `data.<package>.<rule>` across modules.
  - Preserve immutability and reuse of compiled bundles.

## Phase 3 features

- ⬜ Complete OPA built-in function coverage.
- ⬜ Full compliance with OPA test suites and edge cases (wire in OPA's published
  test corpus to convert assumed compatibility into measured coverage; the current
  `opa_compat_spec.rb` is hand-written and narrow).
- ⬜ Partial evaluation and optimization passes.
- ⬜ JSON Schema integration and annotations/metadata.
- ⬜ Policy compiler optimizations for large rule sets.

## Built-in function backlog

~66 of OPA's ~210 builtins are implemented (types, aggregates, numbers, regex,
encoding, strings, collections, comparisons). The registry pattern makes
additions mechanical; this is volume, not difficulty. Highest compat-per-effort first:

- 🟡 Numeric: ✅ `abs`, `round`, `ceil`, `floor`, `numbers.range`; ⬜ `rand.intn`
  (stateful/seeded — deferred), ⬜ `numbers.range_step`.
- 🟡 Regex: ✅ `regex.match`, `regex.is_valid`, `regex.split`, `regex.find_n`,
  `regex.replace` (Go `Expand` template syntax; Go `(?P<name>)` named groups rewritten to
  plain captures with `${name}` resolved via a name→index map; RE2 zero-width-match
  semantics); ⬜ `regex.find_all_string_submatch_n`, `regex.template_match`,
  `regex.globs_match`.
- 🟡 Encoding: ✅ `json.marshal`/`json.unmarshal`/`json.is_valid`, `base64`
  encode/decode/is_valid, `base64url` encode/decode, `hex` encode/decode,
  `urlquery` encode/decode; ⬜ `yaml.*`, ⬜ `urlquery.encode_object`/`decode_object`,
  ⬜ `base64url.encode_no_pad`.

## Refactoring follow-ups

- Extract a shared `Builtins::StringHelpers.string_value` (mirroring
  `NumericHelpers.integer_value`) and migrate `codecs.rb` + `regex.rb`'s duplicated
  private `string_arg`. Do both call sites together — not a partial extraction.
- Bound recursion depth in the Value layer (`Value.from_ruby`/`to_ruby`) and other
  recursive evaluator paths. Extremely deeply-nested input (~10k+ levels) currently
  raises an uncatchable `SystemStackError` at value construction — a pre-existing,
  evaluator-wide limitation (OPA bounds this via a nesting limit). Affects any deep
  value, not just `json.marshal`; a shared depth guard would convert it to a clean
  error/undefined.
- Normalize string encoding at the value-ingestion boundary (`StringValue#initialize`
  / `Value.from_ruby`) so non-UTF-8 Ruby Strings supplied via the public `input:` API
  behave OPA-faithfully. OPA strings are always UTF-8 (input is JSON); a caller-built
  non-UTF-8 Ruby String currently hashes/encodes its own bytes, diverging from OPA for
  the same logical characters. This is **not** crypto-specific — it affects every string
  builtin identically (`crypto.*`, `base64.encode`, `hex.encode`, `urlquery.encode`,
  `strings.*`). Because normalization at ingestion also changes string **equality,
  hashing, and object-key identity** evaluator-wide, it needs its own design + full
  panel across those surfaces, with an explicit decision on binary/`ASCII-8BIT` input
  (which has no OPA equivalent — transcode-and-undefined vs. hash-raw-bytes). Low
  severity: unreachable through the JSON/Rego input path; requires a hand-built
  non-UTF-8 Ruby String.
- 🟡 Object: ✅ `object.union`, `object.union_n`, `object.filter` (plus object-keys
  support for `object.filter`/`object.remove`); ⬜ `json.patch`, `json.filter`,
  `json.remove` (JSON path / RFC 6902 operations).
- ✅ Strings: `replace`, `trim_prefix`, `trim_suffix`, `strings.count`,
  `strings.reverse`, `indexof_n`, `strings.replace_n`, `strings.any_prefix_match`,
  `strings.any_suffix_match`, regex-backed `regex.split`, and `strings.substring`.
- ✅ Glob: `glob.match`, `glob.quote_meta` (compiled to an anchored Ruby Regexp;
  implements correct glob semantics rather than reproducing gobwas bugs #41/#47 — see
  README known limitations).
- ⬜ Time: `time.now_ns`, `time.parse_rfc3339_ns`, `time.date`, `time.add_date`, etc.
- 🟡 Crypto: ✅ `crypto.md5`, `crypto.sha1`, `crypto.sha256`; ⬜ `crypto.hmac.*`,
  ⬜ `crypto.x509.*`.
- ⬜ Net/CIDR: `net.cidr_contains`, `net.cidr_intersects`, `net.cidr_merge`.
- ✅ Bits: `bits.and`, `bits.or`, `bits.xor`, `bits.negate`, `bits.lsh`, `bits.rsh`
  (`bits.lsh` caps result size as a DoS guard; parser accepts `and`/`or` as dotted
  reference segments so the builtins are callable from source).
- ⬜ Misc: `uuid.rfc4122`, `semver.compare`, `semver.is_valid`, `units.parse*`,
  `graph.reachable`, `walk`.

## Known limitations

- Cross-package function calls are not supported; within-package calls work normally.
- No cross-module cycle detection: cyclic cross-package references stack-overflow
  rather than fail at compile time.
- `with` modifiers are limited and may reset memoization caches.
- No partial evaluation, JSON Schema, or annotation support.
- Performance is slower than OPA for heavy comprehensions.
- Not all OPA built-ins and keywords are implemented yet.

## Community requests

- Richer CLI output formats and policy explanations.
- Deterministic pretty-printer for AST and policies.
- Better compatibility tooling for OPA policy validation.

## Performance improvements

- Memoization improvements for nested rule dependencies.
- Reduce object allocations in evaluator hot paths.
- Add benchmarks for real-world policy suites.
