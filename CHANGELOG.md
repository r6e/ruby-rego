# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Regex built-ins: `regex.match`, `regex.is_valid`, `regex.split`, and
  `regex.find_n`. `regex.split` matches Go's trailing/zero-width/empty-input
  semantics; invalid patterns yield an undefined result. Patterns compile with
  Ruby's regex engine (Onigmo) rather than Go's RE2, so RE2-incompatible
  constructs (lookahead, backreferences) are treated as valid. A per-match
  timeout (RUBY_REGO_REGEX_TIMEOUT, default 1s) yields an undefined result
  instead of hanging on pathological backtracking.
- Numeric built-ins: `abs`, `round`, `ceil`, `floor`, and `numbers.range`,
  matching OPA semantics (round half away from zero; `numbers.range` accepts
  integer-valued bounds and is undefined for a non-integer bound). Non-finite
  inputs and ranges larger than 1,000,000 elements yield an undefined result
  rather than crashing or exhausting memory.
- Multi-module composition: `Ruby::Rego.compile_modules` / `evaluate_modules` compile
  and evaluate a named set of modules with cross-package references and OPA-style
  same-package merge.
- Documentation refresh, architecture notes, and runnable examples.
- YARD documentation for public APIs.

## 0.1.0

### Features

- Lexer, parser, and AST support for core Rego syntax.
- Compiler that validates, indexes, and freezes rules.
- Evaluator with rule execution, unification, and reference resolution.
- Core built-in functions (types, aggregates, strings, collections, comparisons).
- CLI for validation workflows.

### Planned additions

- Expanded built-in function coverage.
- Broader OPA compatibility for advanced keywords and patterns.
- Performance tuning and memoization work.
- Compliance and integration test suites.
