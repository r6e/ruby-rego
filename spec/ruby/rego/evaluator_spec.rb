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

    it "unifies array patterns with values" do
      unification = Ruby::Rego::AST::BinaryOp.new(
        operator: :unify,
        left: Ruby::Rego::AST::ArrayLiteral.new(
          elements: [
            Ruby::Rego::AST::Variable.new(name: "x"),
            Ruby::Rego::AST::NumberLiteral.new(value: 2)
          ]
        ),
        right: Ruby::Rego::AST::ArrayLiteral.new(
          elements: [
            Ruby::Rego::AST::NumberLiteral.new(value: 1),
            Ruby::Rego::AST::NumberLiteral.new(value: 2)
          ]
        )
      )

      eval_node(unification)

      expect(evaluator.environment.lookup("x").to_ruby).to eq(1)
    end

    it "unifies when the variable is on the right" do
      unification = Ruby::Rego::AST::BinaryOp.new(
        operator: :unify,
        left: Ruby::Rego::AST::NumberLiteral.new(value: 1),
        right: Ruby::Rego::AST::Variable.new(name: "x")
      )

      eval_node(unification)

      expect(evaluator.environment.lookup("x").to_ruby).to eq(1)
    end

    it "does not bind ambiguous assignments" do
      assignment = Ruby::Rego::AST::BinaryOp.new(
        operator: :assign,
        left: Ruby::Rego::AST::ObjectLiteral.new(
          pairs: [
            [
              Ruby::Rego::AST::Variable.new(name: "k"),
              Ruby::Rego::AST::NumberLiteral.new(value: 1)
            ]
          ]
        ),
        right: Ruby::Rego::AST::ObjectLiteral.new(
          pairs: [
            [
              Ruby::Rego::AST::StringLiteral.new(value: "a"),
              Ruby::Rego::AST::NumberLiteral.new(value: 1)
            ],
            [
              Ruby::Rego::AST::StringLiteral.new(value: "b"),
              Ruby::Rego::AST::NumberLiteral.new(value: 1)
            ]
          ]
        )
      )

      result = eval_node(assignment)

      expect(result).to be_a(Ruby::Rego::UndefinedValue)
      expect(evaluator.environment.lookup("k")).to be_a(Ruby::Rego::UndefinedValue)
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

    context "when using some declarations with collections" do
      let(:rules) do
        collection = Ruby::Rego::AST::ArrayLiteral.new(
          elements: [
            Ruby::Rego::AST::NumberLiteral.new(value: 1),
            Ruby::Rego::AST::NumberLiteral.new(value: 2)
          ]
        )
        some_decl = Ruby::Rego::AST::SomeDecl.new(
          variables: [Ruby::Rego::AST::Variable.new(name: "x")],
          collection: collection
        )
        condition = Ruby::Rego::AST::BinaryOp.new(
          operator: :unify,
          left: Ruby::Rego::AST::Variable.new(name: "x"),
          right: Ruby::Rego::AST::NumberLiteral.new(value: 2)
        )
        body = [some_decl, Ruby::Rego::AST::QueryLiteral.new(expression: condition)]
        head = { type: :complete, name: "allow", location: nil }

        [Ruby::Rego::AST::Rule.new(name: "allow", head: head, body: body)]
      end

      it "iterates bindings to satisfy the rule body" do
        result = evaluator.evaluate

        expect(result.success?).to be(true)
        expect(result.value.to_ruby["allow"]).to be(true)
      end
    end

    context "when binding array index and value" do
      let(:rules) do
        collection = Ruby::Rego::AST::ArrayLiteral.new(
          elements: [
            Ruby::Rego::AST::NumberLiteral.new(value: 1),
            Ruby::Rego::AST::NumberLiteral.new(value: 2)
          ]
        )
        some_decl = Ruby::Rego::AST::SomeDecl.new(
          variables: [
            Ruby::Rego::AST::Variable.new(name: "i"),
            Ruby::Rego::AST::Variable.new(name: "v")
          ],
          collection: collection
        )
        index_condition = Ruby::Rego::AST::BinaryOp.new(
          operator: :unify,
          left: Ruby::Rego::AST::Variable.new(name: "i"),
          right: Ruby::Rego::AST::NumberLiteral.new(value: 1)
        )
        value_condition = Ruby::Rego::AST::BinaryOp.new(
          operator: :unify,
          left: Ruby::Rego::AST::Variable.new(name: "v"),
          right: Ruby::Rego::AST::NumberLiteral.new(value: 2)
        )
        body = [
          some_decl,
          Ruby::Rego::AST::QueryLiteral.new(expression: index_condition),
          Ruby::Rego::AST::QueryLiteral.new(expression: value_condition)
        ]
        head = { type: :complete, name: "allow", location: nil }

        [Ruby::Rego::AST::Rule.new(name: "allow", head: head, body: body)]
      end

      it "binds index/value pairs for arrays" do
        result = evaluator.evaluate

        expect(result.success?).to be(true)
        expect(result.value.to_ruby["allow"]).to be(true)
      end
    end

    context "when binding set members" do
      let(:rules) do
        collection = Ruby::Rego::AST::SetLiteral.new(
          elements: [
            Ruby::Rego::AST::NumberLiteral.new(value: 1),
            Ruby::Rego::AST::NumberLiteral.new(value: 2)
          ]
        )
        some_decl = Ruby::Rego::AST::SomeDecl.new(
          variables: [Ruby::Rego::AST::Variable.new(name: "x")],
          collection: collection
        )
        condition = Ruby::Rego::AST::BinaryOp.new(
          operator: :unify,
          left: Ruby::Rego::AST::Variable.new(name: "x"),
          right: Ruby::Rego::AST::NumberLiteral.new(value: 1)
        )
        body = [some_decl, Ruby::Rego::AST::QueryLiteral.new(expression: condition)]
        head = { type: :complete, name: "allow", location: nil }

        [Ruby::Rego::AST::Rule.new(name: "allow", head: head, body: body)]
      end

      it "iterates set values" do
        result = evaluator.evaluate

        expect(result.success?).to be(true)
        expect(result.value.to_ruby["allow"]).to be(true)
      end
    end

    context "when binding object keys and values" do
      let(:rules) do
        collection = Ruby::Rego::AST::ObjectLiteral.new(
          pairs: [
            [
              Ruby::Rego::AST::StringLiteral.new(value: "a"),
              Ruby::Rego::AST::NumberLiteral.new(value: 1)
            ]
          ]
        )
        some_decl = Ruby::Rego::AST::SomeDecl.new(
          variables: [
            Ruby::Rego::AST::Variable.new(name: "k"),
            Ruby::Rego::AST::Variable.new(name: "v")
          ],
          collection: collection
        )
        key_condition = Ruby::Rego::AST::BinaryOp.new(
          operator: :unify,
          left: Ruby::Rego::AST::Variable.new(name: "k"),
          right: Ruby::Rego::AST::StringLiteral.new(value: "a")
        )
        value_condition = Ruby::Rego::AST::BinaryOp.new(
          operator: :unify,
          left: Ruby::Rego::AST::Variable.new(name: "v"),
          right: Ruby::Rego::AST::NumberLiteral.new(value: 1)
        )
        body = [
          some_decl,
          Ruby::Rego::AST::QueryLiteral.new(expression: key_condition),
          Ruby::Rego::AST::QueryLiteral.new(expression: value_condition)
        ]
        head = { type: :complete, name: "allow", location: nil }

        [Ruby::Rego::AST::Rule.new(name: "allow", head: head, body: body)]
      end

      it "iterates object key/value pairs" do
        result = evaluator.evaluate

        expect(result.success?).to be(true)
        expect(result.value.to_ruby["allow"]).to be(true)
      end
    end
  end
end

# rubocop:enable Metrics/BlockLength
