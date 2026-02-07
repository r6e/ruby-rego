# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Compiler do
  let(:compiler) { described_class.new }
  let(:package) { Ruby::Rego::AST::Package.new(path: ["example"]) }

  def module_with(rules)
    Ruby::Rego::AST::Module.new(package: package, imports: [], rules: rules)
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

    it "detects conflicting complete rules" do
      rules = [
        complete_rule(name: "allow", value: boolean(true)),
        complete_rule(name: "allow", value: boolean(false))
      ]

      expect { compiler.compile(module_with(rules)) }
        .to raise_error(Ruby::Rego::CompilationError, /Conflicting complete rules/)
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
  end
end

# rubocop:enable Metrics/BlockLength
