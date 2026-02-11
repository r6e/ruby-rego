# TODO

## Phase 2 features

- Full `every` keyword semantics and test coverage.
- Rule heads with references (indexing and evaluation).
- Advanced pattern matching and destructuring in rule bodies.
- Expanded built-in function set (strings, objects, arrays, conversions).
- Broader `with` keyword support across evaluator paths.

## Phase 3 features

- Complete OPA built-in function coverage.
- Full compliance with OPA test suites and edge cases.
- Partial evaluation and optimization passes.
- JSON Schema integration and annotations.
- Policy compiler optimizations for large rule sets.

## Known limitations

- `with` modifiers are limited and may reset memoization caches.
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
