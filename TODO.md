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
- ⬜ **Multi-module composition (top priority).** Today `compile(source)` takes a
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

~46 of OPA's ~210 builtins are implemented (types, aggregates, strings,
collections, comparisons). The registry pattern makes additions mechanical;
this is volume, not difficulty. Highest compatibility-per-effort first:

- ⬜ Numeric: `abs`, `round`, `ceil`, `floor`, `numbers.range`, `rand.intn`.
- ⬜ Regex: `regex.match`, `regex.find_n`, `regex.split`, `regex.replace`, etc.
- ⬜ Encoding: `json.marshal`/`json.unmarshal`, `yaml.*`, `base64*`, `hex`, `urlquery`.
- ⬜ Object: `object.union`, `object.union_n`, `object.filter`, `json.patch`,
  `json.filter`, `json.remove`.
- ⬜ Strings: `replace`, `trim_prefix`, `trim_suffix`, substring `count`,
  regex-backed splits.
- ⬜ Glob: `glob.match`, `glob.quote_meta`.
- ⬜ Time: `time.now_ns`, `time.parse_rfc3339_ns`, `time.date`, `time.add_date`, etc.
- ⬜ Crypto: `crypto.md5`, `crypto.sha1`, `crypto.sha256`, `crypto.hmac.*`.
- ⬜ Net/CIDR: `net.cidr_contains`, `net.cidr_intersects`, `net.cidr_merge`.
- ⬜ Bits: `bits.and`, `bits.or`, `bits.xor`, `bits.lsh`, `bits.rsh`.
- ⬜ Misc: `uuid.rfc4122`, `semver.compare`, `semver.is_valid`, `units.parse*`,
  `graph.reachable`, `walk`.

## Known limitations

- Single-module only: cannot evaluate a set of policy files that reference each
  other across packages (see Phase 2 multi-module item).
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
