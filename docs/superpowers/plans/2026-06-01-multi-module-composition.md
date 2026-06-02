# Multi-Module Composition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compile and evaluate a named set of Rego modules `{name => source}` that reference each other across packages, with OPA-style same-package merge, while leaving the existing single-module `compile`/`evaluate` API byte-for-byte unchanged.

**Architecture:** A new immutable `CompiledPolicySet` holds `{package_key => CompiledModule}`. `Compiler#compile_set` parses each source, merges same-package modules at the AST level, and compiles each via the existing single-module path. The `Evaluator` gains a `for_policy_set` constructor that builds one evaluation context (resolver + rule provider + rule evaluator) per module, shares one `Environment`/memoization across them, and wires a `ModuleContextRegistry` so a reference like `data.b.x` from package `a` is delegated to `b`'s resolver. Cross-package resolution is a pure fallback that is inert when only one module is present, so the single-module path is untouched.

**Tech Stack:** Ruby, RSpec, RBS/Steep, RuboCop, Reek.

---

## Background the implementer must know

Read these files before starting; the tasks reference their exact methods:

- `lib/ruby/rego.rb` — top-level `compile`/`evaluate`/`parse`.
- `lib/ruby/rego/compiler.rb` — `Compiler#compile(ast_module)`, `CompilationArtifacts` (Struct: `rules_by_name, package_path, dependency_graph`), `CompiledModuleBuilder.build(ast_module, artifacts)`.
- `lib/ruby/rego/compiled_module.rb` — `CompiledModule` (`package_path`, `rules_by_name`, `imports`, `dependency_graph`).
- `lib/ruby/rego/evaluator.rb` — `Evaluator#initialize(compiled_module, input:, data:)`, `build_evaluators`, `build_expression_evaluator`, `evaluate_rules`, `evaluate_query`.
- `lib/ruby/rego/evaluator/reference_resolver.rb` — `resolve`, `resolve_reference_value`, `resolve_rule_reference`, `rule_reference`, `package_rule_reference`, `package_match?`.
- `lib/ruby/rego/evaluator/rule_value_provider.rb` — `value_for`, `memoized_value_for`, cache key is currently the bare rule name.
- `lib/ruby/rego/ast/module.rb`, `ast/package.rb`, `ast/import.rb` — `AST::Module.new(package:, imports:, rules:, location:)`; `Package#path` is `Array<String>`.

Key facts:
- `environment.memoization.context.rule_values` is a single shared `Hash[String => Value]`. Multiple modules sharing it will collide on duplicate rule names unless keys are package-qualified (Task 3).
- The single-module no-query result (`evaluate_rules`) is a **flat** `{rule_name => value}` hash, NOT nested by package. The policy-set path produces a **nested** `{package => {... => value}}` result via a separate constructor, so single-module behavior is preserved (Task 6).
- `package_path` is `Array<String>`; the `package_key` used throughout is `package_path.join(".")`.

Run the full suite at the start to confirm a green baseline:

```bash
bundle exec rspec
```
Expected: `392 examples, 0 failures`.

---

## File Structure

- Create `lib/ruby/rego/compiled_policy_set.rb` — `CompiledPolicySet` container + longest-prefix lookup helper.
- Create `lib/ruby/rego/evaluator/module_context_registry.rb` — maps `package_key => ReferenceResolver` for cross-package delegation.
- Modify `lib/ruby/rego/compiler.rb` — add `compile_set(modules)` + same-package AST merge.
- Modify `lib/ruby/rego/evaluator/rule_value_provider.rb` — package-qualified cache key.
- Modify `lib/ruby/rego/evaluator/reference_resolver.rb` — cross-package fallback.
- Modify `lib/ruby/rego/evaluator.rb` — `for_policy_set` constructor, per-module contexts, nested no-query results, query routing.
- Modify `lib/ruby/rego.rb` — `compile_modules` / `evaluate_modules`, plus the new `require_relative`s.
- Modify `sig/ruby/rego.rbs` — signatures for the new symbols.
- Create `spec/ruby/rego/compiled_policy_set_spec.rb`, `spec/ruby/rego/evaluator/module_context_registry_spec.rb`.
- Create `spec/features/multi_module_spec.rb` — integration coverage.

---

### Task 1: `CompiledPolicySet` container

**Files:**
- Create: `lib/ruby/rego/compiled_policy_set.rb`
- Test: `spec/ruby/rego/compiled_policy_set_spec.rb`

- [ ] **Step 1: Write the failing test**

```ruby
# spec/ruby/rego/compiled_policy_set_spec.rb
# frozen_string_literal: true

require "spec_helper"

RSpec.describe Ruby::Rego::CompiledPolicySet do
  def compiled(package_path)
    Ruby::Rego::CompiledModule.new(package_path: package_path, rules_by_name: {})
  end

  it "indexes modules by joined package key" do
    authz = compiled(%w[acme authz])
    users = compiled(%w[acme users])
    set = described_class.new([authz, users])

    expect(set.modules.length).to eq(2)
    expect(set.module_for(%w[acme authz allow])).to be(authz)
    expect(set.module_for(%w[acme users alice])).to be(users)
  end

  it "returns the longest matching package prefix" do
    parent = compiled(%w[acme])
    child = compiled(%w[acme authz])
    set = described_class.new([parent, child])

    expect(set.module_for(%w[acme authz allow])).to be(child)
    expect(set.module_for(%w[acme other])).to be(parent)
  end

  it "returns nil when no package owns the keys" do
    set = described_class.new([compiled(%w[acme authz])])
    expect(set.module_for(%w[other thing])).to be_nil
  end

  it "exposes package keys" do
    set = described_class.new([compiled(%w[acme authz])])
    expect(set.package_keys).to eq(["acme.authz"])
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bundle exec rspec spec/ruby/rego/compiled_policy_set_spec.rb`
Expected: FAIL — `uninitialized constant Ruby::Rego::CompiledPolicySet`.

- [ ] **Step 3: Write minimal implementation**

```ruby
# lib/ruby/rego/compiled_policy_set.rb
# frozen_string_literal: true

module Ruby
  module Rego
    # Immutable set of compiled modules keyed by package path.
    class CompiledPolicySet
      # @param modules [Array<CompiledModule>] compiled modules
      def initialize(modules)
        by_key = {} # @type var by_key: Hash[String, CompiledModule]
        modules.each { |mod| by_key[mod.package_path.join(".")] = mod }
        @modules_by_key = by_key.freeze
      end

      # @return [Array<CompiledModule>]
      def modules
        modules_by_key.values
      end

      # @return [Array<String>]
      def package_keys
        modules_by_key.keys
      end

      # Find the module whose package path is the longest prefix of keys.
      #
      # @param keys [Array<Object>] reference key list
      # @return [CompiledModule, nil]
      def module_for(keys)
        key = self.class.longest_prefix_key(package_keys, keys)
        key && modules_by_key[key]
      end

      # Find the package key whose path is the longest prefix of keys.
      #
      # @param package_keys [Array<String>] candidate package keys
      # @param keys [Array<Object>] reference key list
      # @return [String, nil]
      def self.longest_prefix_key(package_keys, keys)
        string_keys = keys.map(&:to_s)
        best = nil # @type var best: String?
        package_keys.each do |package_key|
          segments = package_key.split(".")
          length = segments.length
          next unless string_keys.length > length && string_keys[0, length] == segments
          next if best && best.split(".").length >= length

          best = package_key
        end
        best
      end

      private

      attr_reader :modules_by_key
    end
  end
end
```

- [ ] **Step 4: Wire the require and run the test**

Add to `lib/ruby/rego.rb` immediately after the `require_relative "rego/compiled_module"` line:

```ruby
require_relative "rego/compiled_policy_set"
```

Run: `bundle exec rspec spec/ruby/rego/compiled_policy_set_spec.rb`
Expected: PASS (4 examples).

- [ ] **Step 5: Commit**

```bash
git add lib/ruby/rego/compiled_policy_set.rb spec/ruby/rego/compiled_policy_set_spec.rb lib/ruby/rego.rb
git commit -m "feat: add CompiledPolicySet with longest-prefix module lookup"
```

---

### Task 2: `Compiler#compile_set` with same-package merge

**Files:**
- Modify: `lib/ruby/rego/compiler.rb`
- Test: `spec/ruby/rego/compiler_spec.rb` (append)

- [ ] **Step 1: Write the failing test**

```ruby
# Append inside spec/ruby/rego/compiler_spec.rb's top-level describe block.
RSpec.describe "Ruby::Rego::Compiler#compile_set" do
  let(:compiler) { Ruby::Rego::Compiler.new }

  it "compiles distinct packages into a set" do
    set = compiler.compile_set(
      "a.rego" => "package a\nallow := true\n",
      "b.rego" => "package b\ndeny := false\n"
    )

    expect(set).to be_a(Ruby::Rego::CompiledPolicySet)
    expect(set.package_keys).to contain_exactly("a", "b")
  end

  it "merges rules from files sharing a package" do
    set = compiler.compile_set(
      "one.rego" => "package shared\nfoo := 1\n",
      "two.rego" => "package shared\nbar := 2\n"
    )

    mod = set.module_for(%w[shared foo])
    expect(mod.rule_names).to contain_exactly("foo", "bar")
  end

  it "merges imports from files sharing a package" do
    set = compiler.compile_set(
      "one.rego" => "package shared\nimport data.x\nfoo := 1\n",
      "two.rego" => "package shared\nimport data.y\nbar := 2\n"
    )

    mod = set.module_for(%w[shared foo])
    expect(mod.imports.length).to eq(2)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bundle exec rspec spec/ruby/rego/compiler_spec.rb -e compile_set`
Expected: FAIL — `undefined method 'compile_set'`.

- [ ] **Step 3: Write minimal implementation**

In `lib/ruby/rego/compiler.rb`, add this public method directly after the existing `compile(ast_module)` method (around line 39):

```ruby
      # Compile a named set of module sources into a policy set.
      #
      # @param modules [Hash{String => String}] map of name => Rego source
      # @return [CompiledPolicySet] compiled policy set
      def compile_set(modules)
        ast_modules = parse_named_modules(modules)
        merged = merge_modules_by_package(ast_modules)
        CompiledPolicySet.new(merged.map { |ast_module| compile(ast_module) })
      end
```

Add these private helpers in the `private` section of `Compiler` (after `compile_rules`):

```ruby
      def parse_named_modules(modules)
        modules.map do |name, source|
          ErrorHandling.wrap(name.to_s) do
            tokens = Lexer.new(source).tokenize
            Parser.new(tokens).parse
          end
        end
      end

      def merge_modules_by_package(ast_modules)
        grouped = ast_modules.group_by { |ast_module| ast_module.package.path }
        grouped.map do |_path, group|
          next group.first if group.length == 1

          merge_group(group)
        end
      end

      def merge_group(group)
        first = group.first
        AST::Module.new(
          package: first.package,
          imports: group.flat_map(&:imports),
          rules: group.flat_map(&:rules),
          location: first.location
        )
      end
```

Add `require_relative "lexer"` and `require_relative "parser"` to the top of `lib/ruby/rego/compiler.rb` if not already present (check the existing `require_relative` block; `ast`, `compiled_module`, `errors` are there — add `lexer`, `parser`, and `compiled_policy_set`):

```ruby
require_relative "lexer"
require_relative "parser"
require_relative "compiled_policy_set"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bundle exec rspec spec/ruby/rego/compiler_spec.rb -e compile_set`
Expected: PASS (3 examples).

- [ ] **Step 5: Commit**

```bash
git add lib/ruby/rego/compiler.rb spec/ruby/rego/compiler_spec.rb
git commit -m "feat: add Compiler#compile_set with same-package merge"
```

---

### Task 3: Package-qualified memoization key in `RuleValueProvider`

This prevents `acme.authz.allow` and `acme.users.allow` from colliding in the shared `rule_values` cache. The change is internal; with one module the key string changes but behavior is identical.

**Files:**
- Modify: `lib/ruby/rego/evaluator/rule_value_provider.rb`
- Test: `spec/ruby/rego/evaluator/rule_value_provider_spec.rb` (create)

- [ ] **Step 1: Write the failing test**

```ruby
# spec/ruby/rego/evaluator/rule_value_provider_spec.rb
# frozen_string_literal: true

require "spec_helper"

RSpec.describe Ruby::Rego::Evaluator::RuleValueProvider do
  it "does not collide cache entries for same rule name in different packages" do
    memo = Ruby::Rego::Memoization::Store.new

    provider_a = described_class.new(rules_by_name: {}, memoization: memo, package_key: "a")
    provider_b = described_class.new(rules_by_name: {}, memoization: memo, package_key: "b")

    fake_a = Class.new { def evaluate_group(_rules) = Ruby::Rego::Value.from_ruby("from_a") }.new
    fake_b = Class.new { def evaluate_group(_rules) = Ruby::Rego::Value.from_ruby("from_b") }.new
    provider_a.instance_variable_set(:@rules_by_name, { "allow" => [:rule] })
    provider_b.instance_variable_set(:@rules_by_name, { "allow" => [:rule] })
    provider_a.attach(fake_a)
    provider_b.attach(fake_b)

    expect(provider_a.value_for("allow").to_ruby).to eq("from_a")
    expect(provider_b.value_for("allow").to_ruby).to eq("from_b")
  end

  it "defaults package_key to empty when not given" do
    provider = described_class.new(rules_by_name: {}, memoization: nil)
    expect(provider.rule_defined?("x")).to be(false)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bundle exec rspec spec/ruby/rego/evaluator/rule_value_provider_spec.rb`
Expected: FAIL — `unknown keyword: :package_key` (and/or collision: both return `"from_a"`).

- [ ] **Step 3: Write minimal implementation**

Edit `lib/ruby/rego/evaluator/rule_value_provider.rb`. Change the constructor and the cache key:

```ruby
        # @param rules_by_name [Hash{String => Array<AST::Rule>}]
        # @param memoization [Memoization::Store, nil]
        # @param package_key [String] package key used to namespace cache entries
        def initialize(rules_by_name:, memoization: nil, package_key: "")
          @rules_by_name = rules_by_name
          @memoization = memoization
          @package_key = package_key
          @rule_evaluator = nil
        end
```

Add `:package_key` to the `attr_reader` line:

```ruby
        attr_reader :memoization, :rule_evaluator, :rules_by_name, :package_key
```

Replace `memoized_value_for`:

```ruby
        def memoized_value_for(name)
          memo = memoization
          return evaluate_value_for(name) unless memo

          cache = memo.context.rule_values
          cache_key = "#{package_key} #{name}"
          cache.fetch(cache_key) { |_key| cache[cache_key] = evaluate_value_for(name) }
        end
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bundle exec rspec spec/ruby/rego/evaluator/rule_value_provider_spec.rb`
Expected: PASS (2 examples).

- [ ] **Step 5: Verify no regression on full suite**

Run: `bundle exec rspec`
Expected: `392 examples, 0 failures` (the existing single-module callers still pass `RuleValueProvider.new(rules_by_name:, memoization:)`; `package_key` defaults to `""`).

- [ ] **Step 6: Commit**

```bash
git add lib/ruby/rego/evaluator/rule_value_provider.rb spec/ruby/rego/evaluator/rule_value_provider_spec.rb
git commit -m "feat: namespace rule memoization cache by package key"
```

---

### Task 4: `ModuleContextRegistry`

**Files:**
- Create: `lib/ruby/rego/evaluator/module_context_registry.rb`
- Test: `spec/ruby/rego/evaluator/module_context_registry_spec.rb`

- [ ] **Step 1: Write the failing test**

```ruby
# spec/ruby/rego/evaluator/module_context_registry_spec.rb
# frozen_string_literal: true

require "spec_helper"

RSpec.describe Ruby::Rego::Evaluator::ModuleContextRegistry do
  it "returns the resolver for the longest matching package" do
    resolver_a = Object.new
    resolver_b = Object.new
    registry = described_class.new("acme" => resolver_a, "acme.authz" => resolver_b)

    expect(registry.resolver_for(%w[acme authz allow])).to be(resolver_b)
    expect(registry.resolver_for(%w[acme other])).to be(resolver_a)
  end

  it "returns nil when no package owns the keys" do
    registry = described_class.new("acme.authz" => Object.new)
    expect(registry.resolver_for(%w[other thing])).to be_nil
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bundle exec rspec spec/ruby/rego/evaluator/module_context_registry_spec.rb`
Expected: FAIL — `uninitialized constant ...ModuleContextRegistry`.

- [ ] **Step 3: Write minimal implementation**

```ruby
# lib/ruby/rego/evaluator/module_context_registry.rb
# frozen_string_literal: true

require_relative "../compiled_policy_set"

module Ruby
  module Rego
    class Evaluator
      # Maps package keys to reference resolvers for cross-package dispatch.
      class ModuleContextRegistry
        # @param resolvers_by_key [Hash{String => ReferenceResolver}]
        def initialize(resolvers_by_key)
          @resolvers_by_key = resolvers_by_key
          @package_keys = resolvers_by_key.keys
        end

        # Find the resolver whose package is the longest prefix of keys.
        #
        # @param keys [Array<Object>] reference key list
        # @return [ReferenceResolver, nil]
        def resolver_for(keys)
          key = CompiledPolicySet.longest_prefix_key(package_keys, keys)
          key && resolvers_by_key[key]
        end

        private

        attr_reader :resolvers_by_key, :package_keys
      end
    end
  end
end
```

Add to `lib/ruby/rego/evaluator.rb` `require_relative` block (near the other `evaluator/...` requires):

```ruby
require_relative "evaluator/module_context_registry"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bundle exec rspec spec/ruby/rego/evaluator/module_context_registry_spec.rb`
Expected: PASS (2 examples).

- [ ] **Step 5: Commit**

```bash
git add lib/ruby/rego/evaluator/module_context_registry.rb spec/ruby/rego/evaluator/module_context_registry_spec.rb lib/ruby/rego/evaluator.rb
git commit -m "feat: add ModuleContextRegistry for cross-package dispatch"
```

---

### Task 5: Cross-package fallback in `ReferenceResolver`

Adds an opt-in fallback: when a `data.<pkg>...` reference is not owned by this resolver's own package and a registry is attached, delegate to the owning module's resolver. With no registry attached (single-module path), the fallback is inert.

**Files:**
- Modify: `lib/ruby/rego/evaluator/reference_resolver.rb`

This task is verified through the integration test in Task 6 (a resolver needs a fully built module context to exercise meaningfully). Implement the seam here; do not commit until Task 6's integration test passes. Make the edits, then run the full suite to confirm no single-module regression, then move to Task 6.

- [ ] **Step 1: Add the registry attachment point and fallback**

In `reference_resolver.rb`, add to `initialize` (after `@import_map = build_import_map(imports)`):

```ruby
          @module_resolver = nil
```

Add a public attach method right after `initialize` (before `resolve`):

```ruby
        # Attach the cross-package module registry.
        #
        # @param module_resolver [ModuleContextRegistry]
        # @return [void]
        def attach_module_resolver(module_resolver)
          @module_resolver = module_resolver
        end
```

Add `:module_resolver` to the private `attr_reader` line:

```ruby
        attr_reader :environment, :package_path, :rule_value_provider, :key_resolver, :import_map, :memoization, :module_resolver
```

Replace `resolve_reference_value` with the version that adds the cross-package fallback as the last rule-resolution step (before falling through to data-path `resolved`):

```ruby
        def resolve_reference_value(ref)
          import_value = resolve_import_reference(ref)
          return import_value if import_value

          rule_value = resolve_rule_reference_without_data(ref)
          return rule_value if rule_value

          base_value = environment.resolve_reference(ref.base)
          resolved = resolve_reference_path_fast(base_value, ref)
          rule_value = resolve_rule_reference(ref)
          return rule_value if rule_value

          cross_value = resolve_cross_package_reference(ref)
          return cross_value if cross_value

          resolved
        end
```

Add the new private method (next to `resolve_rule_reference`):

```ruby
        def resolve_cross_package_reference(ref)
          resolver = module_resolver
          return nil unless resolver

          base = ref.base
          return nil unless base.is_a?(AST::Variable) && base.name == "data"

          keys = valid_reference_keys(ref.path)
          return nil unless keys

          owner = resolver.resolver_for(keys)
          return nil if owner.nil? || owner.equal?(self)

          owner.resolve(ref)
        end
```

Rationale: `owner.resolve(ref)` re-enters the owning module's resolver, whose `package_path` matches the reference, so it resolves via the owner's rule provider and imports. Cycles route through the same shared memoization as local self-references and therefore behave identically (see Task 8).

- [ ] **Step 2: Run the full suite to confirm no single-module regression**

Run: `bundle exec rspec`
Expected: `392 examples, 0 failures` (no registry is attached on the single-module path, so `resolve_cross_package_reference` returns `nil` immediately).

- [ ] **Step 3: Do NOT commit yet** — proceed to Task 6, which builds the wiring and the integration test that exercises this code, then commit Tasks 5 + 6 together.

---

### Task 6: `Evaluator.for_policy_set` — contexts, registry, nested results, query routing

**Files:**
- Modify: `lib/ruby/rego/evaluator.rb`
- Test: `spec/features/multi_module_spec.rb` (create)

- [ ] **Step 1: Write the failing integration test**

```ruby
# spec/features/multi_module_spec.rb
# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Multi-module evaluation" do
  def evaluate(modules, query:, input: {}, data: {})
    set = Ruby::Rego::Compiler.new.compile_set(modules)
    Ruby::Rego::Evaluator.for_policy_set(set, input: input, data: data).evaluate(query)
  end

  it "resolves a cross-package reference" do
    result = evaluate(
      {
        "authz.rego" => <<~REGO,
          package acme.authz
          allow if data.acme.users.is_admin
        REGO
        "users.rego" => <<~REGO
          package acme.users
          is_admin if input.user == "root"
        REGO
      },
      query: "data.acme.authz.allow",
      input: { "user" => "root" }
    )

    expect(result.value.to_ruby).to be(true)
  end

  it "returns nested results keyed by package for the no-query path" do
    set = Ruby::Rego::Compiler.new.compile_set(
      "a.rego" => "package a\nfoo := 1\n",
      "b.rego" => "package b\nbar := 2\n"
    )
    result = Ruby::Rego::Evaluator.for_policy_set(set, input: {}, data: {}).evaluate

    expect(result.value.to_ruby).to eq(
      "a" => { "foo" => 1 },
      "b" => { "bar" => 2 }
    )
  end

  it "evaluates a merged same-package set" do
    result = evaluate(
      {
        "one.rego" => "package shared\nfoo := 1\n",
        "two.rego" => "package shared\nbar := foo + 1\n"
      },
      query: "data.shared.bar"
    )

    expect(result.value.to_ruby).to eq(2)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bundle exec rspec spec/features/multi_module_spec.rb`
Expected: FAIL — `undefined method 'for_policy_set'`.

- [ ] **Step 3: Implement `for_policy_set` and supporting methods**

In `lib/ruby/rego/evaluator.rb`, add the class method near `from_ast` (after it):

```ruby
      # Build an evaluator over a compiled policy set.
      #
      # @param policy_set [CompiledPolicySet]
      # @param input [Object] input document
      # @param data [Object] data document
      # @return [Evaluator]
      def self.for_policy_set(policy_set, input: {}, data: {})
        evaluator = allocate
        evaluator.send(:initialize_with_policy_set, policy_set, input: input, data: data)
        evaluator
      end
```

Add the private initializer and the multi-module context machinery. Place these in the `private` section of `Evaluator`:

```ruby
      def initialize_with_policy_set(policy_set, input:, data:)
        @policy_set = policy_set
        @compiled_module = nil
        @environment = Environment.new(input: input, data: data, rules: {})
        @module_contexts = build_module_contexts(policy_set)
        attach_module_registry(@module_contexts)
        primary = @module_contexts.first
        @expression_evaluator = primary && primary.fetch(:expression_evaluator)
        @rule_evaluator = primary && primary.fetch(:rule_evaluator)
      end
      private :initialize_with_policy_set

      def build_module_contexts(policy_set)
        policy_set.modules.map { |mod| build_module_context(mod) }
      end

      def build_module_context(mod)
        package_key = mod.package_path.join(".")
        rule_value_provider = RuleValueProvider.new(
          rules_by_name: mod.rules_by_name,
          memoization: environment.memoization,
          package_key: package_key
        )
        reference_resolver = ReferenceResolver.new(
          environment: @environment,
          package_path: mod.package_path,
          rule_value_provider: rule_value_provider,
          imports: mod.imports,
          memoization: environment.memoization
        )
        expression_evaluator = ExpressionEvaluator.new(
          environment: @environment,
          reference_resolver: reference_resolver
        )
        rule_evaluator = RuleEvaluator.new(
          environment: @environment,
          expression_evaluator: expression_evaluator
        )
        rule_value_provider.attach(rule_evaluator)
        expression_evaluator.attach_query_evaluator(rule_evaluator)
        {
          module: mod,
          package_key: package_key,
          reference_resolver: reference_resolver,
          expression_evaluator: expression_evaluator,
          rule_evaluator: rule_evaluator
        }
      end

      def attach_module_registry(contexts)
        resolvers_by_key = contexts.each_with_object({}) do |context, acc|
          acc[context.fetch(:package_key)] = context.fetch(:reference_resolver)
        end
        registry = ModuleContextRegistry.new(resolvers_by_key)
        contexts.each { |context| context.fetch(:reference_resolver).attach_module_resolver(registry) }
      end
```

Now route evaluation. Change `evaluate` to dispatch on whether this is a policy set. Replace the existing `evaluate` method body:

```ruby
      def evaluate(query = nil)
        environment.memoization.reset!
        return evaluate_policy_set(query) if policy_set

        value, bindings = query ? evaluate_query(query) : [evaluate_rules, nil]
        return nil if query && value.is_a?(UndefinedValue)

        ResultBuilder.new(value, bindings).build
      end
```

Add `attr_reader :policy_set` (or `attr_reader :policy_set, :module_contexts`) and the policy-set evaluation methods in `private`:

```ruby
      attr_reader :policy_set, :module_contexts

      def evaluate_policy_set(query)
        return evaluate_policy_set_query(query) if query

        value = evaluate_policy_set_rules
        ResultBuilder.new(value, nil).build
      end

      def evaluate_policy_set_query(query)
        context = context_for_query(query)
        return nil unless context

        evaluator = context.fetch(:expression_evaluator)
        node = QueryNodeBuilder.new(query).build
        bindings = evaluator.eval_with_unification(node, environment).first || {}
        value = evaluator.evaluate(node)
        return nil if value.is_a?(UndefinedValue)

        ResultBuilder.new(value, bindings).build
      end

      def context_for_query(query)
        keys = query.to_s.split(".")
        keys = keys[1..] || [] if keys.first == "data"
        mod = policy_set.module_for(keys)
        return context_by_module(mod) if mod

        module_contexts.first
      end

      def context_by_module(mod)
        module_contexts.find { |context| context.fetch(:module).equal?(mod) }
      end

      def evaluate_policy_set_rules
        tree = {} # @type var tree: Hash[String, untyped]
        module_contexts.each do |context|
          rules_value = evaluate_module_rules(context)
          next if rules_value.empty?

          assign_package_subtree(tree, context.fetch(:module).package_path, rules_value)
        end
        Value.from_ruby(tree)
      end

      def evaluate_module_rules(context)
        evaluator = context.fetch(:rule_evaluator)
        mod = context.fetch(:module)
        results = {} # @type var results: Hash[String, untyped]
        mod.rules_by_name.each do |name, rules|
          value = evaluator.evaluate_group(rules)
          results[name] = value.to_ruby unless value.is_a?(UndefinedValue)
        end
        results
      end

      def assign_package_subtree(tree, package_path, rules_value)
        node = tree
        package_path[0...-1].each do |segment|
          node = (node[segment] ||= {})
        end
        node[package_path.last] = rules_value
      end
```

Note: `Evaluator#initialize` (the single-module constructor) must set `@policy_set = nil` so the dispatch in `evaluate` works. Add `@policy_set = nil` as the first line of the existing `initialize` and of `initialize_with_environment`.

- [ ] **Step 4: Run the integration test**

Run: `bundle exec rspec spec/features/multi_module_spec.rb`
Expected: PASS (3 examples).

- [ ] **Step 5: Run the full suite**

Run: `bundle exec rspec`
Expected: `0 failures` (existing single-module count + new examples).

- [ ] **Step 6: Commit Tasks 5 and 6 together**

```bash
git add lib/ruby/rego/evaluator/reference_resolver.rb lib/ruby/rego/evaluator.rb spec/features/multi_module_spec.rb
git commit -m "feat: evaluate compiled policy sets with cross-package references"
```

---

### Task 7: Public API — `compile_modules` / `evaluate_modules`

**Files:**
- Modify: `lib/ruby/rego.rb`
- Test: `spec/ruby/rego/public_api_spec.rb` (append)

- [ ] **Step 1: Write the failing test**

```ruby
# Append to spec/ruby/rego/public_api_spec.rb inside the top-level describe.
RSpec.describe "Ruby::Rego multi-module public API" do
  let(:modules) do
    {
      "authz.rego" => "package acme.authz\nallow if data.acme.users.is_admin\n",
      "users.rego" => "package acme.users\nis_admin if input.user == \"root\"\n"
    }
  end

  it "compile_modules returns a CompiledPolicySet" do
    expect(Ruby::Rego.compile_modules(modules)).to be_a(Ruby::Rego::CompiledPolicySet)
  end

  it "compile still returns a CompiledModule" do
    expect(Ruby::Rego.compile("package a\nallow := true\n")).to be_a(Ruby::Rego::CompiledModule)
  end

  it "evaluate_modules resolves cross-package references" do
    result = Ruby::Rego.evaluate_modules(modules, input: { "user" => "root" }, query: "data.acme.authz.allow")
    expect(result.value.to_ruby).to be(true)
  end
end
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bundle exec rspec spec/ruby/rego/public_api_spec.rb -e multi-module`
Expected: FAIL — `undefined method 'compile_modules'`.

- [ ] **Step 3: Implement the public methods**

In `lib/ruby/rego.rb`, add inside `class << self` after `compile`:

```ruby
      # Compile a named set of module sources into a policy set.
      #
      # @param modules [Hash{String => String}] map of name => Rego source
      # @return [CompiledPolicySet] compiled policy set
      def compile_modules(modules)
        ErrorHandling.wrap("compilation") do
          Compiler.new.compile_set(modules)
        end
      end
```

And after `evaluate`:

```ruby
      # Evaluate a named set of modules against input and data.
      #
      # @param modules [Hash{String => String}] map of name => Rego source
      # @param input [Object] input document
      # @param data [Object] data document
      # @param query [Object, nil] optional query path
      # @return [Result, nil] evaluation result, or nil when a query is undefined
      # :reek:LongParameterList
      def evaluate_modules(modules, input: {}, data: {}, query: nil)
        policy_set = compile_modules(modules)
        ErrorHandling.wrap("evaluation") do
          Evaluator.for_policy_set(policy_set, input: input, data: data).evaluate(query)
        end
      end
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bundle exec rspec spec/ruby/rego/public_api_spec.rb`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/ruby/rego.rb spec/ruby/rego/public_api_spec.rb
git commit -m "feat: add Ruby::Rego.compile_modules and evaluate_modules"
```

---

### Task 8: Same-package conflict naming, import isolation, undefined & cycle behavior

**Files:**
- Test: `spec/features/multi_module_spec.rb` (append)
- Possibly modify: `lib/ruby/rego/compiler.rb` (only if conflict error does not already name the file)

- [ ] **Step 1: Write the tests**

```ruby
# Append to spec/features/multi_module_spec.rb.
RSpec.describe "Multi-module edge cases" do
  let(:compiler) { Ruby::Rego::Compiler.new }

  def evaluate(modules, query:, input: {})
    set = compiler.compile_set(modules)
    Ruby::Rego::Evaluator.for_policy_set(set, input: input, data: {}).evaluate(query)
  end

  it "raises when same-package files define conflicting complete rules" do
    expect do
      compiler.compile_set(
        "one.rego" => "package shared\nallow := true\n",
        "two.rego" => "package shared\nallow := false\n"
      )
    end.to raise_error(Ruby::Rego::CompilationError)
  end

  it "isolates same-named imports across modules" do
    result = evaluate(
      {
        "a.rego" => <<~REGO,
          package a
          import data.source.left as picked
          value := picked
        REGO
        "b.rego" => <<~REGO,
          package b
          import data.source.right as picked
          value := picked
        REGO
        "source.rego" => <<~REGO
          package source
          left := "L"
          right := "R"
        REGO
      },
      query: "data.a.value"
    )

    expect(result.value.to_ruby).to eq("L")
  end

  it "returns undefined for a reference to a non-existent package rule" do
    result = evaluate(
      { "a.rego" => "package a\nallow if data.missing.flag\n" },
      query: "data.a.allow"
    )
    expect(result).to be_nil
  end

  it "handles a cross-package reference cycle the same way as a local self-cycle" do
    local_cycle = lambda do
      Ruby::Rego.evaluate("package a\nx if x\n", query: "data.a.x")
    end
    cross_cycle = lambda do
      evaluate(
        {
          "a.rego" => "package a\nx if data.b.y\n",
          "b.rego" => "package b\ny if data.a.x\n"
        },
        query: "data.a.x"
      )
    end

    # Characterize local behavior, then assert the cross-package path matches it.
    local_error = nil
    begin
      local_cycle.call
    rescue StandardError => e
      local_error = e.class
    end

    if local_error
      expect { cross_cycle.call }.to raise_error(local_error)
    else
      expect { cross_cycle.call }.not_to raise_error
    end
  end
end
```

- [ ] **Step 2: Run the tests**

Run: `bundle exec rspec spec/features/multi_module_spec.rb`
Expected: the conflict, import-isolation, and undefined tests PASS. The cycle test characterizes current behavior and asserts parity.

- [ ] **Step 3: Adjust only if a test fails**

- If the conflict test does not raise: the merge in Task 2 must run before `compile`, and `compile`'s existing `ConflictChecker` should fire. Confirm `merge_group` unions rules so both `allow` definitions land in one rule group. No new conflict logic should be needed.
- If the cycle test reveals an unbounded recursion that crashes the process rather than raising a catchable `StandardError` (e.g. a hard `SystemStackError`): note it in the PR body as a known limitation (cross-module cycle detection is a follow-up; same as the existing local behavior). Do not add new cycle detection in this PR — it is out of scope per the spec.

- [ ] **Step 4: Commit**

```bash
git add spec/features/multi_module_spec.rb lib/ruby/rego/compiler.rb
git commit -m "test: cover multi-module conflicts, import isolation, undefined and cycles"
```

---

### Task 9: RBS signatures + quality gates

**Files:**
- Modify: `sig/ruby/rego.rbs`
- Possibly create: `sig/ruby/rego/compiled_policy_set.rbs` etc. — follow the existing single-file convention in `sig/ruby/rego.rbs` (the repo keeps signatures inline in that file; add there).

- [ ] **Step 1: Add signatures**

In `sig/ruby/rego.rbs`, alongside the existing `self.compile` / `self.evaluate` (lines 5–7), add:

```rbs
    def self.compile_modules: (Hash[String, String] modules) -> CompiledPolicySet
    def self.evaluate_modules: (Hash[String, String] modules, ?input: untyped, ?data: untyped, ?query: untyped) -> (Result | nil)

    class CompiledPolicySet
      def initialize: (Array[CompiledModule] modules) -> void
      def modules: () -> Array[CompiledModule]
      def package_keys: () -> Array[String]
      def module_for: (Array[untyped] keys) -> CompiledModule?
      def self.longest_prefix_key: (Array[String] package_keys, Array[untyped] keys) -> String?
    end
```

Find the `class Compiler` block in the rbs and add:

```rbs
      def compile_set: (Hash[String, String] modules) -> CompiledPolicySet
```

Find the `class Evaluator` block and add:

```rbs
      def self.for_policy_set: (CompiledPolicySet policy_set, ?input: untyped, ?data: untyped) -> Evaluator
```

Find the `RuleValueProvider` signature and update its initialize to include the new keyword:

```rbs
      def initialize: (rules_by_name: Hash[String, Array[AST::Rule]], ?memoization: untyped, ?package_key: String) -> void
```

Add a signature for `ModuleContextRegistry` and `ReferenceResolver#attach_module_resolver` matching the patterns used for other evaluator inner classes in the file.

- [ ] **Step 2: Run Steep**

Run: `bundle exec steep check`
Expected: no new errors (matching the pre-change baseline; run `bundle exec steep check` on a clean checkout first if unsure what the baseline is).

- [ ] **Step 3: Run RuboCop and Reek**

```bash
bundle exec rubocop lib/ruby/rego/compiled_policy_set.rb lib/ruby/rego/evaluator/module_context_registry.rb lib/ruby/rego/evaluator.rb lib/ruby/rego/evaluator/reference_resolver.rb lib/ruby/rego/evaluator/rule_value_provider.rb lib/ruby/rego/compiler.rb lib/ruby/rego.rb
bundle exec reek lib/ruby/rego/compiled_policy_set.rb lib/ruby/rego/evaluator/module_context_registry.rb
```
Expected: clean, or address offenses (extract methods to satisfy `Metrics`/`reek` as the existing code does — `evaluator.rb` already uses `# rubocop:disable` sparingly; prefer extraction over disables).

- [ ] **Step 4: Full suite + coverage**

Run: `bundle exec rspec`
Expected: `0 failures`, line coverage ≥ 93.9%.

- [ ] **Step 5: Commit**

```bash
git add sig/ruby/rego.rbs
git commit -m "chore: add RBS signatures for multi-module API"
```

---

### Task 10: Docs — README + CHANGELOG + TODO

**Files:**
- Modify: `README.md`, `CHANGELOG.md`, `TODO.md`

- [ ] **Step 1: README** — under "Supported Rego features", add a "Multiple modules" subsection with a `compile_modules` / `evaluate_modules` example mirroring the existing Quick Start style. Note the cross-package reference capability and that the CLI is still single-file.

- [ ] **Step 2: CHANGELOG** — under `## Unreleased`, add:

```markdown
- Multi-module composition: `Ruby::Rego.compile_modules` / `evaluate_modules` compile
  and evaluate a named set of modules with cross-package references and OPA-style
  same-package merge.
```

- [ ] **Step 3: TODO** — change the Phase 2 multi-module item from `⬜` to `✅` and move the "Single-module only" line out of Known limitations (replace with: cross-module cycle detection is not yet implemented).

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md TODO.md
git commit -m "docs: document multi-module composition"
```

---

## Mandatory review before push (per project policy)

Do NOT push until the adversarial review panel converges. Dispatch in parallel, briefed cold (pass the diff, not a summary of fixes):

- `feature-dev:code-reviewer` — bugs/logic/security.
- `feature-dev:code-architect` — design/conventions/API impact (esp. the asymmetric return types and the `for_policy_set` vs `initialize` split).
- `code-simplifier:code-simplifier` — DRY/clarity (esp. duplication between single-module `build_evaluators` and `build_module_context`).
- **Deep-impact tracer** (specialist) — the `ReferenceResolver` change is on a hot path used by every evaluation; verify single-module behavior is provably unchanged and memoization keys can't collide.

Cycle to convergence (R2, R3, …) re-dispatching on each fix commit. Fix forward in this PR. Push only when every reviewer is APPROVED with no open findings.

## Self-review checklist (completed during planning)

- **Spec coverage:** named-map API (Task 7), same-package merge (Task 2), cross-package resolution (Tasks 5–6), back-compat (Tasks 3/5/6 full-suite gates), nested no-query (Task 6), conflict naming + import isolation + undefined + cycle (Task 8), RBS (Task 9). All spec sections map to a task.
- **Placeholders:** none — every code step shows real code.
- **Type consistency:** `package_key` (string, `package_path.join(".")`) and `longest_prefix_key` are used consistently across `CompiledPolicySet`, `ModuleContextRegistry`, and `RuleValueProvider`. `for_policy_set` / `initialize_with_policy_set` / `module_contexts` names are consistent across Task 6.
- **Added beyond spec (justified):** Task 3 (memo key namespacing) and the flat-vs-nested no-query split (Task 6) are correctness requirements the spec implied but did not detail; both are required for correct, back-compat behavior.
