# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Evaluator do
  let(:package) { Ruby::Rego::AST::Package.new(path: ["example"]) }
  let(:module_node) { Ruby::Rego::AST::Module.new(package: package, imports: [], rules: rules) }
  let(:input) { { "user" => { "name" => "admin" }, "roles" => ["admin"] } }
  let(:data) { { "config" => { "enabled" => true } } }
  let(:rules) { [] }
  let(:evaluator) { described_class.new(module_node, input: input, data: data) }

  def eval_node(node)
    evaluator.send(:eval_node, node)
  end

  describe "node evaluation" do
    it "evaluates literals" do
      literal = Ruby::Rego::AST::NumberLiteral.new(value: 42)
      value = eval_node(literal)

      expect(value).to be_a(Ruby::Rego::NumberValue)
      expect(value.to_ruby).to eq(42)
    end

    it "binds and resolves variables" do
      assignment = Ruby::Rego::AST::BinaryOp.new(
        operator: :assign,
        left: Ruby::Rego::AST::Variable.new(name: "x"),
        right: Ruby::Rego::AST::NumberLiteral.new(value: 10)
      )

      eval_node(assignment)

      expect(evaluator.environment.lookup("x").to_ruby).to eq(10)
    end

    it "resolves input and data references" do
      input_reference = Ruby::Rego::AST::Reference.new(
        base: Ruby::Rego::AST::Variable.new(name: "input"),
        path: [
          Ruby::Rego::AST::DotRefArg.new(value: "user"),
          Ruby::Rego::AST::DotRefArg.new(value: "name")
        ]
      )
      data_reference = Ruby::Rego::AST::Reference.new(
        base: Ruby::Rego::AST::Variable.new(name: "data"),
        path: [
          Ruby::Rego::AST::DotRefArg.new(value: "config"),
          Ruby::Rego::AST::DotRefArg.new(value: "enabled")
        ]
      )

      expect(eval_node(input_reference).to_ruby).to eq("admin")
      expect(eval_node(data_reference).to_ruby).to be(true)
    end

    it "evaluates binary operations" do
      addition = Ruby::Rego::AST::BinaryOp.new(
        operator: :plus,
        left: Ruby::Rego::AST::NumberLiteral.new(value: 2),
        right: Ruby::Rego::AST::NumberLiteral.new(value: 3)
      )
      comparison = Ruby::Rego::AST::BinaryOp.new(
        operator: :eq,
        left: Ruby::Rego::AST::StringLiteral.new(value: "a"),
        right: Ruby::Rego::AST::StringLiteral.new(value: "a")
      )

      expect(eval_node(addition).to_ruby).to eq(5)
      expect(eval_node(comparison)).to be_a(Ruby::Rego::BooleanValue)
      expect(eval_node(comparison).to_ruby).to be(true)
    end
  end

  describe "rule evaluation" do
    let(:rules) do
      condition = Ruby::Rego::AST::BinaryOp.new(
        operator: :eq,
        left: Ruby::Rego::AST::Reference.new(
          base: Ruby::Rego::AST::Variable.new(name: "input"),
          path: [
            Ruby::Rego::AST::DotRefArg.new(value: "user"),
            Ruby::Rego::AST::DotRefArg.new(value: "name")
          ]
        ),
        right: Ruby::Rego::AST::StringLiteral.new(value: "admin")
      )
      body = [Ruby::Rego::AST::QueryLiteral.new(expression: condition)]
      head = { type: :complete, name: "allow", location: nil }

      [Ruby::Rego::AST::Rule.new(name: "allow", head: head, body: body)]
    end

    it "evaluates complete rules with simple bodies" do
      result = evaluator.evaluate

      expect(result.success?).to be(true)
      expect(result.value.to_ruby["allow"]).to be(true)
    end
  end
end

# rubocop:enable Metrics/BlockLength
