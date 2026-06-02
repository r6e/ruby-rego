# Multi-module composition — design

**Date:** 2026-06-01
**Status:** Approved, pre-implementation
**Branch:** `feat/multi-module-composition`

## Problem

Today `Ruby::Rego.compile(source)` accepts a single source string and produces one
`CompiledModule` with one package path. `Evaluator` consumes exactly one module.
Real OPA usage composes many `.rego` files into a single `data` namespace where one
package references another (`data.b.allow` from `package a`). Ruby::Rego currently
cannot evaluate a set of policy files that reference each other across packages. This
is the project's largest functional ceiling (see `TODO.md`, Phase 2 top priority).

## Goals

- Compile and evaluate a set of modules supplied as a named map `{ name => source }`.
- Support cross-package references: a rule in `package a` may reference `data.b.x`.
- Support OPA-style same-package merge: multiple files declaring the same package
  union their rules and imports into one logical package.
- Preserve full backward compatibility: `compile(source)` / `evaluate(source, ...)`
  with a single string keep working unchanged.
- Keep compiled artifacts immutable and reusable.

## Non-goals (deferred)

- CLI multi-file support (follow-up PR).
- Partial evaluation, annotations/metadata, bundle/data file loading.
- Builder/`Bundle` object API — the named-map API is the surface for v0.1.
- Unifying `compile`/`compile_modules` return types — `compile` keeps returning
  `CompiledModule`; only the new methods return `CompiledPolicySet`.

## Decisions (from brainstorming)

1. **API shape:** named map `{ name => source }`, mirroring OPA's module set.
   Names give actionable diagnostics (which file). Exposed via **distinct methods**
   `compile_modules` / `evaluate_modules` (Option B); existing `compile` / `evaluate`
   stay `String`-only with unchanged signatures and return types. Chosen over
   type-dispatch on a positional `String | Hash` (Option A) because this gem advertises
   RBS signatures and max type strictness — distinct methods keep each signature a
   single input type and single return type, no union, no overloads. The cost
   (asymmetric return types: `compile -> CompiledModule`, `compile_modules ->
   CompiledPolicySet`) is accepted deliberately: single-module callers keep the simple
   type, multi-module callers opt into the richer one, and nothing breaks.
2. **Same-package handling:** merge OPA-style — union rules and imports across files
   declaring the same package; conflicting complete rules are detected by the existing
   conflict/eval-time machinery, not by a new model.
3. **PR scope:** full vertical slice (named-map API + same-package merge +
   cross-package resolution + multi-module evaluation) in one PR. CLI deferred.
4. **Architecture:** `CompiledPolicySet` container + prefix dispatch (Approach A),
   chosen over flattening to a virtual `data` tree (Approach B). A generalizes the
   existing single-`package_path` prefix match to N modules, keeps per-module import
   scoping automatic, and preserves module identity for diagnostics. B would require
   an AST-rewriting compile pass to fully-qualify imports and would discard module
   names.

## The crux constraint: per-module import scoping

Each module has its own `import` aliases. A rule body in `package authz` that
references alias `users` must resolve it against *that module's* imports, not a global
table. Every component below preserves this by keeping each `CompiledModule`'s imports
with it and evaluating each rule in its owning module's context. This is why Approach A
is preferred — import scoping falls out for free; flattening would break it.

## Components

### New: top-level methods (`lib/ruby/rego.rb`)

- `Ruby::Rego.compile_modules(modules)` — `modules` is `Hash{String => String}` of
  `{ name => source }`; returns `CompiledPolicySet`.
- `Ruby::Rego.evaluate_modules(modules, input:, data:, query:)` — compiles the set and
  evaluates; returns `Result` (or `nil` for an undefined query), same as `evaluate`.

`compile(source)` and `evaluate(source, ...)` are unchanged: `String`-only,
`compile -> CompiledModule`. `Policy` may gain a parallel multi-module entry point in a
follow-up; it is out of scope here.

### New: `CompiledPolicySet` (`lib/ruby/rego/compiled_policy_set.rb`)

Immutable container mapping `package_key => CompiledModule`, where `package_key` is the
joined package path (e.g. `"acme.authz"`). API:

- `module_for(keys)` — returns the `CompiledModule` whose `package_path` is the longest
  prefix of the reference key list `keys`; `nil` if none match. This is the dispatch table.
- `each_module` / `modules` — iteration for top-level `data` evaluation.

### Changed: `Compiler`

Add `compile_set(modules_hash)`:

1. Lex/parse each `{ name => source }` into an AST module (errors name the file).
2. Group AST modules by package path.
3. Merge same-package modules into one AST module per package (union `rules`, union
   `imports`).
4. Run the existing `compile(ast_module)` on each merged module — all current
   validation (conflicts, safety, import-alias checks) runs unchanged.
5. Assemble a `CompiledPolicySet`.

The existing `compile(ast_module)` is untouched and still produces one `CompiledModule`.
Merge happens at the AST level so same-package conflicts across files surface through the
existing `ConflictChecker` for free.

### Changed: `Evaluator`

Accepts a `CompiledModule` (normalized to a one-entry set — full back-compat) or a
`CompiledPolicySet`. Builds **one evaluation context per module**: the existing
`ReferenceResolver` + `RuleValueProvider` + `RuleEvaluator` trio bound to that module's
`package_path`, `imports`, and `rules_by_name`. All contexts share one `Environment` and
one memoization instance.

Top-level `data` evaluation (no query): iterate every module's rules and assemble a nested
result keyed by package path, instead of today's flat single-package hash.

### New: `ModuleContextRegistry` (internal to evaluator)

Holds `{ package_key => context }`. When a `ReferenceResolver` hits a `data.<pkg>.<rule>`
reference whose package prefix isn't its own module, it asks the registry for the owning
module's context and resolves the rule there — using that module's imports and rules.

### Changed: `ReferenceResolver`

Today `package_rule_reference` only matches `@package_path`. It gains a fallback: when the
reference's package prefix is a *different* package, consult the `ModuleContextRegistry`
for that package's context and resolve the rule there. This is the single new wire into
reference resolution.

## Data flow

- **Compile:** `compile_modules({name => source})` → parse each → group by package →
  merge same-package → `compile(merged)` per package → `CompiledPolicySet`.
- **Evaluate `data.acme.authz.allow`:** resolve query path → `module_for(["acme","authz",
  "allow"])` finds `acme.authz` → evaluate `allow` in that module's context.
- **Cross-package ref:** rule in `acme.authz` references `data.acme.users[x]` → resolver
  sees prefix isn't `acme.authz` → registry finds `acme.users` context → resolves `users`
  there with `acme.users`'s own imports. Shared memoization → computed once.
- **Top-level `data`:** iterate all modules' rules → nested result keyed by package path.

The single-module path is "a set with one module," so existing specs exercise the same
code with N=1.

## Error handling

- **Same-package / cross-file conflicts:** ride the existing `ConflictChecker`; raise
  `CompilationError` at compile, naming both contributing modules.
- **Unresolved cross-package reference** (`data.acme.missing.allow`, no owning module):
  resolves to `UndefinedValue` — Rego semantics for a nonexistent rule, not an error.
  Matches missing-local-rule behavior today.
- **Module names in diagnostics:** preserved via the `{name => source}` keys; parse/compile
  errors name the offending file.
- **Import collisions remain per-module:** modules `a` and `b` importing differently-targeted
  `users` aliases do not collide; each compiles with its own import map. Existing per-module
  import-alias validation runs unchanged on each merged module.
- **Cyclic cross-package references** (`a.x` → `b.y` → `a.x`): must trigger the same
  memoization/cycle guard as local cycles, not infinite-loop. Verified with an early probing
  test against current single-module cycle behavior.

## Testing (TDD, outside-in)

1. **Public API specs** — `compile_modules({...})` / `evaluate_modules({...}, query:)` with
   two cooperating packages; assert cross-package resolution works. Assert `compile_modules`
   returns a `CompiledPolicySet` and `compile` still returns a `CompiledModule`.
2. **Same-package merge specs** — one package split across two files; rules from both visible;
   conflicting complete rules raise at compile with both filenames.
3. **Cross-package resolution unit specs** — `CompiledPolicySet#module_for` prefix matching
   (longest-prefix wins; no match → nil); registry dispatch.
4. **Undefined & cycle specs** — missing cross-package ref → undefined; cyclic cross-package
   ref → same guard as local cycles, no hang.
5. **Back-compat** — entire existing suite stays green; single-module path normalized to a
   one-entry set. Regression gate.
6. **Import isolation spec** — two modules with same-named, differently-targeted imports
   resolve independently.

Coverage stays at/above the current ~94%. New files (`CompiledPolicySet`,
`ModuleContextRegistry`) get direct unit specs plus the integration coverage above.

## Backward compatibility

`Ruby::Rego.compile(source: String)` and `.evaluate(source: String, ...)` are unchanged
in signature, return type, and behavior. The new capability is purely additive via the
distinct methods `compile_modules(Hash) -> CompiledPolicySet` and `evaluate_modules(Hash,
...)`. Internally, the `Evaluator` normalizes a single `CompiledModule` to a one-entry
`CompiledPolicySet`, so both paths share evaluation code, but the public single-module
methods continue to return `CompiledModule` to preserve their contract. Each public method
has a single input type and single return type; RBS signatures in `sig/` add the new
methods without widening the existing ones to a union.
