# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Environment do
  let(:input) { { "user" => { "name" => build(:rego_string_value).to_ruby }, "roles" => %w[admin] } }
  let(:data) { { "policies" => { "enabled" => true } } }
  let(:environment) { described_class.new(input: input, data: data) }

  describe "scoping" do
    it "binds and resolves local variables" do
      environment.bind("x", "value")

      expect(environment.lookup("x")).to be_a(Ruby::Rego::StringValue)
      expect(environment.lookup("x").to_ruby).to eq("value")
    end

    it "respects nested scopes" do
      environment.bind("x", "outer")
      environment.push_scope
      environment.bind("x", "inner")

      expect(environment.lookup("x").to_ruby).to eq("inner")

      environment.pop_scope
      expect(environment.lookup("x").to_ruby).to eq("outer")
    end

    it "restores bindings after with_bindings" do
      environment.bind("x", "outer")

      environment.with_bindings("x" => "inner") do
        expect(environment.lookup("x").to_ruby).to eq("inner")
      end

      expect(environment.lookup("x").to_ruby).to eq("outer")
    end
  end

  describe "reserved names" do
    it "returns input and data bindings" do
      expect(environment.lookup("input")).to be_a(Ruby::Rego::ObjectValue)
      expect(environment.lookup("data")).to be_a(Ruby::Rego::ObjectValue)
    end

    it "raises when binding reserved names" do
      expect { environment.bind("input", "override") }
        .to raise_error(Ruby::Rego::Error, /reserved name/)
      expect { environment.bind("data", "override") }
        .to raise_error(Ruby::Rego::Error, /reserved name/)
    end
  end

  describe "reference resolution" do
    it "resolves dot and bracket references" do
      reference = Ruby::Rego::AST::Reference.new(
        base: Ruby::Rego::AST::Variable.new(name: "input"),
        path: [
          Ruby::Rego::AST::DotRefArg.new(value: "user"),
          Ruby::Rego::AST::BracketRefArg.new(value: Ruby::Rego::AST::StringLiteral.new(value: "name"))
        ]
      )

      value = environment.resolve_reference(reference)

      expect(value).to be_a(Ruby::Rego::StringValue)
      expect(value.to_ruby).to eq(input["user"]["name"])
    end

    it "returns undefined for missing paths" do
      reference = Ruby::Rego::AST::Reference.new(
        base: Ruby::Rego::AST::Variable.new(name: "data"),
        path: [Ruby::Rego::AST::DotRefArg.new(value: "missing")]
      )

      value = environment.resolve_reference(reference)

      expect(value).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "uses local bindings in bracket references" do
      environment.bind("idx", 0)
      environment.bind("list", %w[alpha beta])

      reference = Ruby::Rego::AST::Reference.new(
        base: Ruby::Rego::AST::Variable.new(name: "list"),
        path: [Ruby::Rego::AST::BracketRefArg.new(value: Ruby::Rego::AST::Variable.new(name: "idx"))]
      )

      value = environment.resolve_reference(reference)

      expect(value).to be_a(Ruby::Rego::StringValue)
      expect(value.to_ruby).to eq("alpha")
    end
  end

  describe "pooling" do
    it "reuses environments with reset state" do
      pool = Ruby::Rego::EnvironmentPool.new
      state1 = Ruby::Rego::Environment::State.new(
        input: { "user" => "admin" },
        data: {},
        rules: {},
        builtin_registry: Ruby::Rego::Builtins::BuiltinRegistry.instance
      )
      env1 = pool.checkout(state1)
      env1.bind("x", 1)
      pool.checkin(env1)

      state2 = Ruby::Rego::Environment::State.new(
        input: { "user" => "bob" },
        data: {},
        rules: {},
        builtin_registry: Ruby::Rego::Builtins::BuiltinRegistry.instance
      )
      env2 = pool.checkout(state2)

      expect(env2.lookup("x")).to be_a(Ruby::Rego::UndefinedValue)
      expect(env2.input.to_ruby["user"]).to eq("bob")
    end

    it "caps the pool size when max_size is set" do
      pool = Ruby::Rego::EnvironmentPool.new(max_size: 1)
      state1 = Ruby::Rego::Environment::State.new(
        input: { "user" => "admin" },
        data: {},
        rules: {},
        builtin_registry: Ruby::Rego::Builtins::BuiltinRegistry.instance
      )
      state2 = Ruby::Rego::Environment::State.new(
        input: { "user" => "bob" },
        data: {},
        rules: {},
        builtin_registry: Ruby::Rego::Builtins::BuiltinRegistry.instance
      )
      state3 = Ruby::Rego::Environment::State.new(
        input: { "user" => "carol" },
        data: {},
        rules: {},
        builtin_registry: Ruby::Rego::Builtins::BuiltinRegistry.instance
      )

      env1 = pool.checkout(state1)
      env2 = pool.checkout(state2)
      pool.checkin(env1)
      pool.checkin(env2)

      env3 = pool.checkout(state3)

      expect(env3.object_id).to eq(env1.object_id)
    end

    it "raises for negative max_size" do
      expect { Ruby::Rego::EnvironmentPool.new(max_size: -1) }
        .to raise_error(ArgumentError, /max_size/)
    end
  end
end

# rubocop:enable Metrics/BlockLength
