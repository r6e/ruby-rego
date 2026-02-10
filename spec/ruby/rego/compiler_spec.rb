# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Compiler do
  let(:compiler) { described_class.new }
  let(:package) { Ruby::Rego::AST::Package.new(path: ["example"]) }

  def module_with(rules, imports: [])
    Ruby::Rego::AST::Module.new(package: package, imports: imports, rules: rules)
  end

  def string(value)
    Ruby::Rego::AST::StringLiteral.new(value: value)
  end

  def number(value)
    Ruby::Rego::AST::NumberLiteral.new(value: value)
  end

  def boolean(value)
    Ruby::Rego::AST::BooleanLiteral.new(value: value)
  end

  def array_literal(elements)
    Ruby::Rego::AST::ArrayLiteral.new(elements: elements)
  end

  def call(name, args)
    Ruby::Rego::AST::Call.new(
      name: Ruby::Rego::AST::Variable.new(name: name),
      args: args,
      location: nil
    )
  end

  def reference_call(segments, args)
    base, *path = segments
    name = Ruby::Rego::AST::Reference.new(
      base: Ruby::Rego::AST::Variable.new(name: base),
      path: path.map { |segment| Ruby::Rego::AST::DotRefArg.new(value: segment) }
    )
    Ruby::Rego::AST::Call.new(name: name, args: args, location: nil)
  end

  def variable(name)
    Ruby::Rego::AST::Variable.new(name: name)
  end

  def query(expression)
    Ruby::Rego::AST::QueryLiteral.new(expression: expression)
  end

  def function_rule(name:, args:, value:)
    head = { type: :function, name: name, args: args, value: value, location: nil }
    Ruby::Rego::AST::Rule.new(name: name, head: head, body: nil)
  end

  def import(path, alias_name: nil)
    Ruby::Rego::AST::Import.new(path: path, alias_name: alias_name, location: nil)
  end

  def default_rule(name:, value:)
    head = { type: :complete, name: name, value: value, default: true, location: nil }
    Ruby::Rego::AST::Rule.new(name: name, head: head, body: nil, default_value: value)
  end

  def data_ref(*segments)
    Ruby::Rego::AST::Reference.new(
      base: Ruby::Rego::AST::Variable.new(name: "data"),
      path: segments.map { |segment| Ruby::Rego::AST::DotRefArg.new(value: segment) }
    )
  end

  def input_ref(*segments)
    Ruby::Rego::AST::Reference.new(
      base: Ruby::Rego::AST::Variable.new(name: "input"),
      path: segments.map { |segment| Ruby::Rego::AST::DotRefArg.new(value: segment) }
    )
  end

  def complete_rule(name:, body: nil, value: nil)
    head = { type: :complete, name: name, value: value, location: nil }
    Ruby::Rego::AST::Rule.new(name: name, head: head, body: body)
  end

  def partial_set_rule(name:, term:)
    head = { type: :partial_set, name: name, term: term, location: nil }
    Ruby::Rego::AST::Rule.new(name: name, head: head, body: nil)
  end

  def partial_object_rule(name:, key:, value:)
    head = { type: :partial_object, name: name, key: key, value: value, location: nil }
    Ruby::Rego::AST::Rule.new(name: name, head: head, body: nil)
  end

  describe "#compile" do
    it "indexes rules by name" do
      rules = [
        partial_set_rule(name: "roles", term: string("admin")),
        partial_set_rule(name: "roles", term: string("user")),
        complete_rule(name: "allow", body: [query(boolean(true))])
      ]

      compiled = compiler.compile(module_with(rules))

      expect(compiled.lookup_rule("roles").length).to eq(2)
      expect(compiled.rule_names).to contain_exactly("roles", "allow")
      expect(compiled.has_rule?("allow")).to be(true)
    end

    it "defers conflicting complete rules to evaluation" do
      rules = [
        complete_rule(name: "allow", value: boolean(true)),
        complete_rule(name: "allow", value: boolean(false))
      ]

      compiled = compiler.compile(module_with(rules))
      evaluator = Ruby::Rego::Evaluator.new(compiled)

      expect { evaluator.evaluate }
        .to raise_error(Ruby::Rego::EvaluationError, /Conflicting values/)
    end

    it "detects conflicting rule types" do
      rules = [
        complete_rule(name: "allow", value: boolean(true)),
        partial_set_rule(name: "allow", term: string("admin"))
      ]

      expect { compiler.compile(module_with(rules)) }
        .to raise_error(Ruby::Rego::CompilationError, /Conflicting rule types/)
    end

    it "detects conflicting function arities" do
      rules = [
        function_rule(name: "check", args: [variable("x")], value: boolean(true)),
        function_rule(name: "check", args: [variable("x"), variable("y")], value: boolean(false))
      ]

      expect { compiler.compile(module_with(rules)) }
        .to raise_error(Ruby::Rego::CompilationError, /Conflicting function arity/)
    end

    it "rejects function names that conflict with builtins" do
      rules = [function_rule(name: "count", args: [variable("x")], value: boolean(true))]

      expect { compiler.compile(module_with(rules)) }
        .to raise_error(Ruby::Rego::CompilationError, /Function name conflicts with builtin/)
    end

    it "rejects duplicate import aliases" do
      imports = [
        import(%w[data users], alias_name: "users"),
        import(%w[data roles], alias_name: "users")
      ]

      expect { compiler.compile(module_with([], imports: imports)) }
        .to raise_error(Ruby::Rego::CompilationError, /Duplicate import alias/)
    end

    it "rejects import aliases that conflict with rule names" do
      imports = [import(%w[data users], alias_name: "allow")]
      rules = [complete_rule(name: "allow", value: boolean(true))]

      expect { compiler.compile(module_with(rules, imports: imports)) }
        .to raise_error(Ruby::Rego::CompilationError, /Import alias conflicts with rule name/)
    end

    it "rejects import aliases that shadow reserved names" do
      imports = [import(%w[data users], alias_name: "input")]

      expect { compiler.compile(module_with([], imports: imports)) }
        .to raise_error(Ruby::Rego::CompilationError, /Import alias conflicts with reserved name/)
    end

    it "allows importing reserved roots without aliases" do
      imports = [import(%w[data]), import(%w[input])]

      expect { compiler.compile(module_with([], imports: imports)) }.not_to raise_error
    end

    it "detects multiple default rules" do
      rules = [
        default_rule(name: "allow", value: boolean(true)),
        default_rule(name: "allow", value: boolean(false))
      ]

      expect { compiler.compile(module_with(rules)) }
        .to raise_error(Ruby::Rego::CompilationError, /Conflicting default rules/)
    end

    it "merges incremental rules during evaluation" do
      rules = [
        partial_set_rule(name: "roles", term: string("admin")),
        partial_set_rule(name: "roles", term: string("user")),
        partial_object_rule(name: "users", key: string("alice"), value: string("admin")),
        partial_object_rule(name: "users", key: string("bob"), value: string("user"))
      ]

      compiled = compiler.compile(module_with(rules))
      evaluator = Ruby::Rego::Evaluator.new(compiled)
      result = evaluator.evaluate

      expect(result.value.to_ruby["roles"]).to eq(Set.new(%w[admin user]))
      expect(result.value.to_ruby["users"]).to eq({ "alice" => "admin", "bob" => "user" })
    end

    it "builds a dependency graph for rule references" do
      rules = [
        complete_rule(name: "users", body: [query(boolean(true))]),
        complete_rule(name: "allow", body: [query(data_ref("users"))])
      ]

      compiled = compiler.compile(module_with(rules))

      expect(compiled.dependency_graph["allow"]).to contain_exactly("users")
      expect(compiled.dependency_graph["users"]).to eq([])
      expect(compiled.dependency_graph).to be_frozen
      compiled.dependency_graph.each_value do |deps|
        expect(deps).to be_frozen
      end
    end

    it "validates safety by requiring bound variables" do
      unbound_expr = Ruby::Rego::AST::BinaryOp.new(
        operator: :eq,
        left: variable("x"),
        right: number(1)
      )
      rules = [complete_rule(name: "allow", body: [query(unbound_expr)])]

      expect { compiler.compile(module_with(rules)) }
        .to raise_error(Ruby::Rego::CompilationError, /unbound variables x/)
    end

    it "allows default rules with comprehensions" do
      comprehension = Ruby::Rego::AST::ArrayComprehension.new(
        term: string("value"),
        body: [query(input_ref("user"))]
      )
      rules = [default_rule(name: "allow", value: comprehension)]

      expect { compiler.compile(module_with(rules)) }.not_to raise_error
    end

    it "rejects default rules with builtin calls" do
      value = call("count", [array_literal([number(1), number(2)])])
      rules = [default_rule(name: "allow", value: value)]

      expect { compiler.compile(module_with(rules)) }
        .to raise_error(Ruby::Rego::CompilationError, /Default rule values must be ground/)
    end

    it "rejects default rules with namespaced builtin calls" do
      value = reference_call(
        %w[array concat],
        [array_literal([number(1)]), array_literal([number(2)])]
      )
      rules = [default_rule(name: "allow", value: value)]

      expect { compiler.compile(module_with(rules)) }
        .to raise_error(Ruby::Rego::CompilationError, /Default rule values must be ground/)
    end

    it "rejects default rules with references" do
      rules = [default_rule(name: "allow", value: data_ref("defaults", "allow"))]

      expect { compiler.compile(module_with(rules)) }
        .to raise_error(Ruby::Rego::CompilationError, /Default rule values must be ground/)
    end
  end
end

# rubocop:enable Metrics/BlockLength
