# Ruby Rego Gem - Architectural Plan & Strategic Roadmap

## Executive Summary

Building a **pure Ruby implementation** of the full OPA Rego specification is an **extremely ambitious undertaking**. This is comparable in complexity to implementing a full programming language interpreter. Here's my honest assessment and recommended approach:

### Complexity Reality Check

**What you're proposing requires:**

- A full lexer/tokenizer (~1,000-2,000 LOC)
- A complete parser implementing the Rego grammar (~3,000-5,000 LOC)
- An AST representation for all Rego constructs (~2,000-3,000 LOC)
- A type checker (~2,000-4,000 LOC)
- A complete evaluation engine (~5,000-10,000 LOC)
- 100+ built-in functions (~5,000-8,000 LOC)
- Comprehensive test suite (~10,000+ LOC)

**Estimated effort:** 6-12 months of full-time development for a single experienced developer, potentially 12-24 months to reach production quality with full spec compliance.

### Recommended Phased Approach

Given the complexity, I recommend a **pragmatic phased development strategy**:

## Phase 1: Foundation (MVP for 1.0 Release)

### Core Parser & AST

**Priority:** CRITICAL
**Complexity:** High

**Components:**

1. **Lexer/Tokenizer** - Converts Rego source into tokens
2. **Parser** - Builds AST from token stream using recursive descent
3. **AST Nodes** - Ruby classes representing all Rego constructs

**Rego Features to Support:**

- ✅ Basic expressions (literals, variables, references)
- ✅ Operators (==, !=, <, >, <=, >=, +, -, \*, /, %)
- ✅ Arrays, objects, sets
- ✅ Rule definitions (complete and partial)
- ✅ Comprehensions (array, object, set)
- ✅ Package and import declarations
- ✅ Boolean logic (if, not, some)
- ⚠️ Built-in functions (start with ~20 most common)
- ⚠️ `with` keyword (defer complex cases)
- ❌ `every` keyword (Phase 2)
- ❌ Rule heads with references (Phase 2)
- ❌ Advanced pattern matching (Phase 2)

### Basic Evaluator

**Priority:** CRITICAL
**Complexity:** Very High

**Components:**

1. **Environment/Context** - Manages variable bindings, input, data
2. **Expression Evaluator** - Evaluates AST nodes to values
3. **Unification Engine** - Pattern matching and variable binding
4. **Rule Evaluation** - Incremental and complete definitions

**Core Capabilities:**

- Variable assignment and scoping
- Reference resolution (input._, data._)
- Rule evaluation with backtracking
- Set/object/array operations
- Basic unification

### Essential Built-ins (Phase 1)

**Priority:** HIGH
**Count:** ~20 functions

Focus on most commonly used:

- Type checking: `is_string`, `is_number`, `is_boolean`, `is_array`, `is_object`, `is_set`, `is_null`
- Collections: `count`, `sum`, `max`, `min`, `sort`
- Strings: `contains`, `startswith`, `endswith`, `lower`, `upper`, `split`, `concat`
- Aggregation: `all`, `any`

## Phase 2: Advanced Features (Post-1.0)

- `every` keyword support
- Rule heads with references
- Advanced comprehensions
- Pattern destructuring
- Template strings
- Additional 50+ built-in functions
- Performance optimizations

## Phase 3: Full Specification (Long-term)

- Complete built-in function library (100+)
- JSON Schema integration
- Metadata and annotations
- Full `with` keyword semantics
- Optimization passes
- Partial evaluation

---

## Detailed Architecture

### Directory Structure

```plaintext
ruby-rego/
├── lib/
│   └── ruby/
│       └── rego/
│           ├── version.rb
│           ├── lexer.rb           # Tokenization
│           ├── token.rb           # Token definitions
│           ├── parser.rb          # Parser (AST builder)
│           ├── ast/               # AST node definitions
│           │   ├── base.rb
│           │   ├── module.rb
│           │   ├── rule.rb
│           │   ├── expression.rb
│           │   ├── literal.rb
│           │   ├── reference.rb
│           │   ├── comprehension.rb
│           │   └── ...
│           ├── evaluator.rb       # Main evaluation engine
│           ├── environment.rb     # Variable/rule storage
│           ├── builtins/          # Built-in functions
│           │   ├── registry.rb
│           │   ├── aggregates.rb
│           │   ├── strings.rb
│           │   ├── types.rb
│           │   └── ...
│           ├── unifier.rb         # Unification/pattern matching
│           ├── errors.rb          # Custom exceptions
│           └── api.rb             # High-level public API
├── exe/
│   └── rego-validate              # CLI executable
├── spec/
│   ├── lexer_spec.rb
│   ├── parser_spec.rb
│   ├── evaluator_spec.rb
│   ├── integration/
│   │   └── opa_compliance_spec.rb
│   └── fixtures/
│       ├── policies/
│       └── data/
└── README.md
```

### Core Components

#### 1. Lexer (`lib/ruby/rego/lexer.rb`)

```ruby
module Ruby
  module Rego
    class Lexer
      # Converts Rego source code into tokens
      # Handles: keywords, operators, literals, identifiers, whitespace

      def initialize(source)
        @source = source
        @position = 0
        @line = 1
        @column = 1
      end

      def tokenize
        tokens = []
        until eof?
          tokens << next_token
        end
        tokens << Token.new(:EOF, nil, @line, @column)
      end

      private

      def next_token
        skip_whitespace_and_comments
        # Token recognition logic
      end
    end
  end
end
```

#### 2. Parser (`lib/ruby/rego/parser.rb`)

```ruby
module Ruby
  module Rego
    class Parser
      # Recursive descent parser following Rego grammar
      # Produces AST from token stream

      def initialize(tokens)
        @tokens = tokens
        @position = 0
      end

      def parse
        # Returns AST::Module
        parse_module
      end

      private

      def parse_module
        # module = package { import } policy
      end

      def parse_rule
        # rule = [ "default" ] rule-head { rule-body }
      end

      def parse_expr
        # Operator precedence parsing
      end
    end
  end
end
```

#### 3. AST Nodes (`lib/ruby/rego/ast/`)

```ruby
module Ruby
  module Rego
    module AST
      class Base
        attr_reader :location

        def initialize(location: nil)
          @location = location
        end

        def accept(visitor)
          visitor.visit(self)
        end
      end

      class Module < Base
        attr_reader :package, :imports, :rules
      end

      class Rule < Base
        attr_reader :name, :head, :body, :default, :else_clause
      end

      class Expression < Base
        # Base for all expressions
      end

      # ... many more node types
    end
  end
end
```

#### 4. Evaluator (`lib/ruby/rego/evaluator.rb`)

```ruby
module Ruby
  module Rego
    class Evaluator
      def initialize(ast_module, input: {}, data: {})
        @module = ast_module
        @env = Environment.new(input: input, data: data)
      end

      def evaluate(query = nil)
        # Main evaluation entry point
        # Returns evaluation result
      end

      def eval_rule(rule)
        # Evaluate a single rule
      end

      def eval_expr(expr, env)
        # Evaluate expression in context
        case expr
        when AST::Literal
          expr.value
        when AST::Reference
          resolve_reference(expr, env)
        when AST::BinaryOp
          eval_binary_op(expr, env)
        # ... many more cases
        end
      end

      private

      def resolve_reference(ref, env)
        # Navigate through input/data structures
      end

      def eval_binary_op(op, env)
        left = eval_expr(op.left, env)
        right = eval_expr(op.right, env)
        apply_operator(op.operator, left, right)
      end
    end
  end
end
```

#### 5. Public API (`lib/ruby/rego/api.rb`)

```ruby
module Ruby
  module Rego
    # High-level API for users

    # Parse Rego source into AST
    def self.parse(source)
      tokens = Lexer.new(source).tokenize
      Parser.new(tokens).parse
    end

    # Evaluate Rego policy
    def self.evaluate(source, input: {}, data: {}, query: nil)
      ast = parse(source)
      evaluator = Evaluator.new(ast, input: input, data: data)
      evaluator.evaluate(query)
    end

    # Convenience method for validation use case
    def self.validate(policy:, input:, data: {})
      result = evaluate(policy, input: input, data: data, query: "data.allow")
      result.value == true
    rescue Error => e
      false
    end
  end
end
```

### CLI Executable (`exe/rego-validate`)

```ruby
#!/usr/bin/env ruby

require "ruby/rego"
require "yaml"
require "json"
require "optparse"

options = {
  policy: nil,
  config: nil,
  format: :text
}

OptionParser.new do |opts|
  opts.banner = "Usage: rego-validate --policy POLICY_FILE --config CONFIG_FILE"

  opts.on("--policy FILE", "Rego policy file") do |file|
    options[:policy] = file
  end

  opts.on("--config FILE", "YAML/JSON config file") do |file|
    options[:config] = file
  end

  opts.on("--format FORMAT", [:text, :json], "Output format (text, json)") do |fmt|
    options[:format] = fmt
  end
end.parse!

begin
  # Read files
  policy = File.read(options[:policy])
  config_content = File.read(options[:config])

  # Parse config (YAML or JSON)
  config = if options[:config].end_with?(".json")
    JSON.parse(config_content)
  else
    YAML.safe_load(config_content)
  end

  # Evaluate
  result = Ruby::Rego.evaluate(policy, input: config)

  if options[:format] == :json
    puts JSON.pretty_generate(result.to_h)
    exit(result.success? ? 0 : 1)
  else
    if result.success?
      puts "✓ Validation passed"
      exit 0
    else
      puts "✗ Validation failed"
      result.errors.each { |err| puts "  #{err}" }
      exit 1
    end
  end

rescue Ruby::Rego::Error => e
  if options[:format] == :json
    puts JSON.pretty_generate({error: e.message, line: e.line, column: e.column})
  else
    puts "Error: #{e.message}"
    puts "  at line #{e.line}, column #{e.column}" if e.line
  end
  exit 2
end
```

---

## Implementation Priorities & Timeline

### Phase 1: MVP (Months 1-4)

#### Month 1: Lexer & Basic Parser

- Implement tokenizer for all Rego tokens
- Build parser for basic rules and expressions
- Create AST node hierarchy
- Unit tests for lexer and parser

#### Month 2: Core Evaluator

- Environment and variable binding
- Expression evaluation
- Reference resolution
- Basic rule evaluation

#### Month 3: Essential Features

- Comprehensions
- Unification engine
- `some` and `not` keywords
- 20 core built-in functions

#### Month 4: Polish & CLI

- Error handling and reporting
- CLI executable
- Integration tests
- Documentation

### Phase 2: Expansion (Months 5-8)

- Additional built-in functions (50+)
- `every` keyword
- `with` keyword complete support
- Performance optimizations
- Advanced pattern matching

### Phase 3: Full Compliance (Months 9-12)

- Remaining built-in functions
- Edge cases and spec compliance
- Comprehensive test suite against OPA test cases
- Optimization and profiling

---

## Key Technical Challenges

### 1. **Unification Engine**

Rego's pattern matching is complex. Need to implement:

- Variable binding with backtracking
- Multiple solution generation
- Conflict detection

### 2. **Incremental Rule Definitions**

Rules with same name must be merged correctly.

### 3. **Reference Resolution**

Dynamic references like `data[x][y]` require careful handling.

### 4. **Performance**

Pure Ruby will be slower than Go. Focus on:

- Memoization of evaluated rules
- Lazy evaluation where possible
- Efficient data structures

### 5. **Built-in Functions**

This is the most labor-intensive part. Each function needs:

- Implementation
- Type checking
- Error handling
- Tests

---

## Testing Strategy

### 1. **Unit Tests**

- Every AST node
- Every evaluator component
- Each built-in function

### 2. **Integration Tests**

- End-to-end policy evaluation
- Complex real-world policies

### 3. **Compliance Tests**

- Port OPA's official test suite
- Compare results with `opa eval`

### 4. **Performance Benchmarks**

- Track evaluation speed
- Memory usage profiling

---

## Risk Mitigation

### Risk 1: Scope Creep

**Mitigation:** Strict feature prioritization, MVP-first approach

### Risk 2: Performance Issues

**Mitigation:** Profile early, consider native extensions for hot paths if needed

### Risk 3: Spec Changes

**Mitigation:** Pin to specific OPA version initially (e.g., 0.60.0)

### Risk 4: Complexity Underestimation

**Mitigation:** Weekly progress reviews, adjust timeline as needed

---

## Success Criteria for v1.0

✅ **Parser**: Handles 90%+ of common Rego syntax
✅ **Evaluator**: Correctly evaluates policies with:

- Basic rules and expressions
- Comprehensions
- 20+ built-in functions
  ✅ **API**: Clean, Ruby-idiomatic interface
  ✅ **CLI**: Working validation executable
  ✅ **Tests**: 80%+ code coverage
  ✅ **Docs**: Complete API documentation and examples
