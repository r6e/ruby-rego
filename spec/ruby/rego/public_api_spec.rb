# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego do
  let(:policy_source) do
    <<~REGO
      package example
      default allow = false
      allow { input.user == "admin" }
    REGO
  end

  describe ".parse" do
    it "parses source into an AST module" do
      ast_module = described_class.parse(policy_source)

      expect(ast_module).to be_a(Ruby::Rego::AST::Module)
      expect(ast_module.package.path).to eq(["example"])
      expect(ast_module.rules.map(&:name)).to include("allow")
    end

    it "surfaces parsing errors with locations" do
      error = nil

      begin
        described_class.parse("package")
      rescue Ruby::Rego::ParserError => e
        error = e
      end

      expect(error).to be_a(Ruby::Rego::ParserError)
      expect(error.location).not_to be_nil
    end
  end

  describe ".compile" do
    it "compiles source into a compiled module" do
      compiled = described_class.compile(policy_source)

      expect(compiled).to be_a(Ruby::Rego::CompiledModule)
      expect(compiled.rule_names).to include("allow")
    end
  end

  describe ".evaluate" do
    it "evaluates a policy end-to-end" do
      result = described_class.evaluate(
        policy_source,
        input: { "user" => "admin" },
        query: "data.example.allow"
      )

      expect(result.success?).to be(true)
      expect(result.value.to_ruby).to be(true)
    end

    it "handles input and data together" do
      source = <<~REGO
        package example
        allow { input.user == data.admin }
      REGO

      result = described_class.evaluate(
        source,
        input: { "user" => "admin" },
        data: { "admin" => "admin" },
        query: "data.example.allow"
      )

      expect(result.value.to_ruby).to be(true)
    end

    it "wraps unexpected errors with a friendly error" do
      source = <<~REGO
        package example
        allow { true }
      REGO

      expect { described_class.evaluate(source, input: Object.new, query: "data.example.allow") }
        .to raise_error(Ruby::Rego::Error, /Rego evaluation failed/)
    end

    it "returns bindings for assignment queries" do
      query = Ruby::Rego::AST::BinaryOp.new(
        operator: :assign,
        left: Ruby::Rego::AST::Variable.new(name: "x"),
        right: Ruby::Rego::AST::NumberLiteral.new(value: 1)
      )

      result = described_class.evaluate(policy_source, query: query)

      expect(result.bindings["x"]).to be_a(Ruby::Rego::NumberValue)
      expect(result.bindings["x"].to_ruby).to eq(1)
    end
  end
end

RSpec.describe Ruby::Rego::Policy do
  let(:policy_source) do
    <<~REGO
      package example
      default allow = false
      allow { input.user == "admin" }
    REGO
  end

  describe "#evaluate" do
    it "reuses compiled policy across evaluations" do
      policy = described_class.new(policy_source)

      admin_result = policy.evaluate(input: { "user" => "admin" }, query: "data.example.allow")
      user_result = policy.evaluate(input: { "user" => "bob" }, query: "data.example.allow")

      expect(admin_result.value.to_ruby).to be(true)
      expect(user_result.value.to_ruby).to be(false)
    end
  end
end

# rubocop:enable Metrics/BlockLength
