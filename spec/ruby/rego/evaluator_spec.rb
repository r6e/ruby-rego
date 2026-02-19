# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Evaluator do
  let(:package) { Ruby::Rego::AST::Package.new(path: ["example"]) }
  let(:compiled_module) do
    rules_by_name = Ruby::Rego::Compiler.new.index_rules(rules)
    Ruby::Rego::CompiledModule.new(
      package_path: package.path,
      rules_by_name: rules_by_name,
      imports: []
    )
  end
  let(:input) { { "user" => { "name" => "admin" }, "roles" => ["admin"] } }
  let(:data) { { "config" => { "enabled" => true } } }
  let(:rules) { [] }
  let(:evaluator) { described_class.new(compiled_module, input: input, data: data) }

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

  describe "comprehension evaluation" do
    def ast_var(name)
      Ruby::Rego::AST::Variable.new(name: name)
    end

    def ast_number(value)
      Ruby::Rego::AST::NumberLiteral.new(value: value)
    end

    def ast_string(value)
      Ruby::Rego::AST::StringLiteral.new(value: value)
    end

    def ast_array(elements)
      Ruby::Rego::AST::ArrayLiteral.new(elements: elements)
    end

    def ast_object(pairs)
      Ruby::Rego::AST::ObjectLiteral.new(pairs: pairs)
    end

    def ast_set(elements)
      Ruby::Rego::AST::SetLiteral.new(elements: elements)
    end

    def ast_some(variables, collection)
      Ruby::Rego::AST::SomeDecl.new(variables: variables, collection: collection)
    end

    def ast_assign(left, right)
      Ruby::Rego::AST::BinaryOp.new(operator: :assign, left: left, right: right)
    end

    def ast_unify(left, right)
      Ruby::Rego::AST::BinaryOp.new(operator: :unify, left: left, right: right)
    end

    def ast_eq(left, right)
      Ruby::Rego::AST::BinaryOp.new(operator: :eq, left: left, right: right)
    end

    def ast_query_literal(expression)
      Ruby::Rego::AST::QueryLiteral.new(expression: expression)
    end

    it "evaluates array comprehensions" do
      collection = ast_array([ast_number(1), ast_number(2), ast_number(3)])
      some_decl = ast_some([ast_var("x")], collection)
      comp = Ruby::Rego::AST::ArrayComprehension.new(
        term: ast_var("x"),
        body: [some_decl]
      )

      value = eval_node(comp)

      expect(value).to be_a(Ruby::Rego::ArrayValue)
      expect(value.to_ruby).to eq([1, 2, 3])
    end

    it "evaluates set comprehensions" do
      collection = ast_array([ast_number(1), ast_number(1), ast_number(2)])
      some_decl = ast_some([ast_var("x")], collection)
      comp = Ruby::Rego::AST::SetComprehension.new(
        term: ast_var("x"),
        body: [some_decl]
      )

      value = eval_node(comp)

      expect(value).to be_a(Ruby::Rego::SetValue)
      expect(value.to_ruby).to eq(Set.new([1, 2]))
    end

    it "evaluates object comprehensions" do
      collection = ast_object(
        [
          [ast_string("a"), ast_number(1)],
          [ast_string("b"), ast_number(2)]
        ]
      )
      some_decl = ast_some([ast_var("k"), ast_var("v")], collection)
      comp = Ruby::Rego::AST::ObjectComprehension.new(
        term: [ast_var("k"), ast_var("v")],
        body: [some_decl]
      )

      value = eval_node(comp)

      expect(value).to be_a(Ruby::Rego::ObjectValue)
      expect(value.to_ruby).to eq({ "a" => 1, "b" => 2 })
    end

    it "supports nested comprehensions" do
      inner = Ruby::Rego::AST::ArrayComprehension.new(
        term: ast_var("y"),
        body: [ast_query_literal(ast_assign(ast_var("y"), ast_var("x")))]
      )
      outer = Ruby::Rego::AST::ArrayComprehension.new(
        term: inner,
        body: [ast_some([ast_var("x")], ast_array([ast_number(1), ast_number(2)]))]
      )

      value = eval_node(outer)

      expect(value.to_ruby).to eq([[1], [2]])
    end

    it "supports references to outer scope variables" do
      evaluator.environment.bind("threshold", 2)
      collection = ast_array([ast_number(1), ast_number(2), ast_number(3)])
      some_decl = ast_some([ast_var("x")], collection)
      condition = Ruby::Rego::AST::BinaryOp.new(
        operator: :gt,
        left: ast_var("x"),
        right: ast_var("threshold")
      )
      comp = Ruby::Rego::AST::ArrayComprehension.new(
        term: ast_var("x"),
        body: [some_decl, ast_query_literal(condition)]
      )

      value = eval_node(comp)

      expect(value.to_ruby).to eq([3])
    end

    it "respects outer bindings during unification" do
      evaluator.environment.bind("threshold", 2)
      comp = Ruby::Rego::AST::ArrayComprehension.new(
        term: ast_var("x"),
        body: [ast_query_literal(ast_unify(ast_var("x"), ast_var("threshold")))]
      )

      value = eval_node(comp)

      expect(value.to_ruby).to eq([2])
      expect(evaluator.environment.lookup("threshold").to_ruby).to eq(2)
    end

    it "keeps comprehension bindings local" do
      evaluator.environment.bind("x", 99)
      comp = Ruby::Rego::AST::ArrayComprehension.new(
        term: ast_var("x"),
        body: [ast_query_literal(ast_assign(ast_var("x"), ast_number(1)))]
      )

      value = eval_node(comp)

      expect(value.to_ruby).to eq([1])
      expect(evaluator.environment.lookup("x").to_ruby).to eq(99)
    end

    it "skips undefined terms and handles empty results" do
      missing_ref = Ruby::Rego::AST::Reference.new(
        base: ast_var("input"),
        path: [Ruby::Rego::AST::DotRefArg.new(value: "missing")]
      )
      some_decl = ast_some([ast_var("x")], ast_array([ast_number(1)]))
      array_comp = Ruby::Rego::AST::ArrayComprehension.new(
        term: missing_ref,
        body: [some_decl]
      )
      empty_query = ast_query_literal(ast_eq(ast_number(1), ast_number(2)))
      set_comp = Ruby::Rego::AST::SetComprehension.new(
        term: ast_var("x"),
        body: [empty_query]
      )

      expect(eval_node(array_comp).to_ruby).to eq([])
      expect(eval_node(set_comp).to_ruby).to eq(Set.new)
    end

    it "skips undefined keys and values in object comprehensions" do
      missing_ref = Ruby::Rego::AST::Reference.new(
        base: ast_var("input"),
        path: [Ruby::Rego::AST::DotRefArg.new(value: "missing")]
      )
      some_decl = ast_some([ast_var("x")], ast_array([ast_number(1)]))
      missing_key = Ruby::Rego::AST::ObjectComprehension.new(
        term: [missing_ref, ast_var("x")],
        body: [some_decl]
      )
      missing_value = Ruby::Rego::AST::ObjectComprehension.new(
        term: [ast_string("k"), missing_ref],
        body: [some_decl]
      )

      expect(eval_node(missing_key).to_ruby).to eq({})
      expect(eval_node(missing_value).to_ruby).to eq({})
    end

    it "allows false and null keys in object comprehensions" do
      some_decl = ast_some([ast_var("x")], ast_array([ast_number(1)]))
      null_key = Ruby::Rego::AST::NullLiteral.new
      false_key = Ruby::Rego::AST::BooleanLiteral.new(value: false)
      null_comp = Ruby::Rego::AST::ObjectComprehension.new(
        term: [null_key, ast_var("x")],
        body: [some_decl]
      )
      false_comp = Ruby::Rego::AST::ObjectComprehension.new(
        term: [false_key, ast_var("x")],
        body: [some_decl]
      )

      expect(eval_node(null_comp).to_ruby).to eq({ nil => 1 })
      expect(eval_node(false_comp).to_ruby).to eq({ false => 1 })
    end

    it "errors on conflicting object keys" do
      some_decl = ast_some([ast_var("x")], ast_array([ast_number(1), ast_number(2)]))
      comp = Ruby::Rego::AST::ObjectComprehension.new(
        term: [ast_string("a"), ast_var("x")],
        body: [some_decl]
      )

      expect { eval_node(comp) }
        .to raise_error(Ruby::Rego::ObjectKeyConflictError, /Conflicting object keys/)
    end
  end

  describe "every evaluation" do
    def ast_var(name)
      Ruby::Rego::AST::Variable.new(name: name)
    end

    def ast_number(value)
      Ruby::Rego::AST::NumberLiteral.new(value: value)
    end

    def ast_string(value)
      Ruby::Rego::AST::StringLiteral.new(value: value)
    end

    def ast_array(elements)
      Ruby::Rego::AST::ArrayLiteral.new(elements: elements)
    end

    def ast_object(pairs)
      Ruby::Rego::AST::ObjectLiteral.new(pairs: pairs)
    end

    def ast_set(elements)
      Ruby::Rego::AST::SetLiteral.new(elements: elements)
    end

    def ast_eq(left, right)
      Ruby::Rego::AST::BinaryOp.new(operator: :eq, left: left, right: right)
    end

    def ast_neq(left, right)
      Ruby::Rego::AST::BinaryOp.new(operator: :neq, left: left, right: right)
    end

    def ast_gt(left, right)
      Ruby::Rego::AST::BinaryOp.new(operator: :gt, left: left, right: right)
    end

    def ast_assign(left, right)
      Ruby::Rego::AST::BinaryOp.new(operator: :assign, left: left, right: right)
    end

    def ast_query_literal(expression)
      Ruby::Rego::AST::QueryLiteral.new(expression: expression)
    end

    def ast_every(value_var:, domain:, body:, key_var: nil)
      Ruby::Rego::AST::Every.new(
        key_var: key_var,
        value_var: value_var,
        domain: domain,
        body: body
      )
    end

    it "evaluates every with a single variable" do
      domain = ast_array([ast_number(1), ast_number(2), ast_number(3)])
      body = [ast_query_literal(ast_gt(ast_var("x"), ast_number(0)))]
      every = ast_every(value_var: ast_var("x"), domain: domain, body: body)

      value = eval_node(every)

      expect(value).to be_a(Ruby::Rego::BooleanValue)
      expect(value.to_ruby).to be(true)
    end

    it "evaluates every with key/value pairs" do
      domain = ast_object(
        [
          [ast_string("a"), ast_number(1)],
          [ast_string("b"), ast_number(2)]
        ]
      )
      body = [
        ast_query_literal(ast_neq(ast_var("k"), ast_string(""))),
        ast_query_literal(ast_gt(ast_var("v"), ast_number(0)))
      ]
      every = ast_every(value_var: ast_var("v"), key_var: ast_var("k"), domain: domain, body: body)

      value = eval_node(every)

      expect(value.to_ruby).to be(true)
    end

    it "iterates object values when only the value variable is provided" do
      domain = ast_object([[ast_string("a"), ast_number(1)]])
      body = [ast_query_literal(ast_eq(ast_var("v"), ast_number(1)))]
      every = ast_every(value_var: ast_var("v"), domain: domain, body: body)

      value = eval_node(every)

      expect(value.to_ruby).to be(true)
    end

    it "returns true for empty collections" do
      domain = ast_array([])
      body = [ast_query_literal(ast_eq(ast_var("x"), ast_number(1)))]
      every = ast_every(value_var: ast_var("x"), domain: domain, body: body)

      value = eval_node(every)

      expect(value.to_ruby).to be(true)
    end

    it "fails when any body evaluation fails" do
      domain = ast_array([ast_number(1), ast_number(2)])
      body = [ast_query_literal(ast_gt(ast_var("x"), ast_number(1)))]
      every = ast_every(value_var: ast_var("x"), domain: domain, body: body)

      value = eval_node(every)

      expect(value).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "returns undefined when the domain is undefined" do
      domain = ast_var("missing")
      body = [ast_query_literal(ast_eq(ast_var("x"), ast_number(1)))]
      every = ast_every(value_var: ast_var("x"), domain: domain, body: body)

      value = eval_node(every)

      expect(value).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "returns undefined when the domain is not a collection" do
      domain = ast_number(10)
      body = [ast_query_literal(ast_eq(ast_var("x"), ast_number(10)))]
      every = ast_every(value_var: ast_var("x"), domain: domain, body: body)

      value = eval_node(every)

      expect(value).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "returns undefined when set iteration uses key/value variables" do
      domain = ast_set([ast_number(1)])
      body = [ast_query_literal(ast_gt(ast_var("v"), ast_number(0)))]
      every = ast_every(value_var: ast_var("v"), key_var: ast_var("k"), domain: domain, body: body)

      value = eval_node(every)

      expect(value).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "supports nested every expressions" do
      inner = ast_every(
        value_var: ast_var("y"),
        domain: ast_var("x"),
        body: [ast_query_literal(ast_gt(ast_var("y"), ast_number(0)))]
      )
      outer_domain = ast_array(
        [
          ast_array([ast_number(1), ast_number(2)]),
          ast_array([ast_number(3)])
        ]
      )
      outer = ast_every(
        value_var: ast_var("x"),
        domain: outer_domain,
        body: [ast_query_literal(inner)]
      )

      value = eval_node(outer)

      expect(value.to_ruby).to be(true)
    end

    it "keeps every bindings scoped to the body" do
      evaluator.environment.bind("x", 99)
      domain = ast_array([ast_number(1)])
      body = [ast_query_literal(ast_eq(ast_var("x"), ast_number(1)))]
      every = ast_every(value_var: ast_var("x"), domain: domain, body: body)

      value = eval_node(every)

      expect(value.to_ruby).to be(true)
      expect(evaluator.environment.lookup("x").to_ruby).to eq(99)
    end

    it "does not leak bindings from the domain evaluation" do
      evaluator.environment.bind("x", 99)
      domain = ast_assign(ast_var("domain_var"), ast_array([ast_number(1)]))
      body = [ast_query_literal(ast_eq(ast_var("v"), ast_number(1)))]
      every = ast_every(value_var: ast_var("v"), domain: domain, body: body)

      value = eval_node(every)

      expect(value.to_ruby).to be(true)
      expect(evaluator.environment.lookup("x").to_ruby).to eq(99)
      expect(evaluator.environment.lookup("domain_var")).to be_a(Ruby::Rego::UndefinedValue)
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

    context "when destructuring arrays and objects in rule bodies" do
      let(:input) do
        {
          "user" => { "role" => "admin", "id" => 7 },
          "roles" => %w[admin viewer]
        }
      end

      let(:rules) do
        roles_ref = Ruby::Rego::AST::Reference.new(
          base: Ruby::Rego::AST::Variable.new(name: "input"),
          path: [Ruby::Rego::AST::DotRefArg.new(value: "roles")]
        )
        user_ref = Ruby::Rego::AST::Reference.new(
          base: Ruby::Rego::AST::Variable.new(name: "input"),
          path: [Ruby::Rego::AST::DotRefArg.new(value: "user")]
        )
        roles_pattern = Ruby::Rego::AST::ArrayLiteral.new(
          elements: [
            Ruby::Rego::AST::Variable.new(name: "first"),
            Ruby::Rego::AST::Variable.new(name: "_")
          ]
        )
        user_pattern = Ruby::Rego::AST::ObjectLiteral.new(
          pairs: [
            [
              Ruby::Rego::AST::StringLiteral.new(value: "role"),
              Ruby::Rego::AST::Variable.new(name: "role")
            ]
          ]
        )
        roles_assign = Ruby::Rego::AST::BinaryOp.new(operator: :assign, left: roles_pattern, right: roles_ref)
        user_assign = Ruby::Rego::AST::BinaryOp.new(operator: :assign, left: user_pattern, right: user_ref)
        role_check = Ruby::Rego::AST::BinaryOp.new(
          operator: :eq,
          left: Ruby::Rego::AST::Variable.new(name: "role"),
          right: Ruby::Rego::AST::StringLiteral.new(value: "admin")
        )
        body = [
          Ruby::Rego::AST::QueryLiteral.new(expression: roles_assign),
          Ruby::Rego::AST::QueryLiteral.new(expression: user_assign),
          Ruby::Rego::AST::QueryLiteral.new(expression: role_check)
        ]
        head = { type: :complete, name: "allow", location: nil }

        [Ruby::Rego::AST::Rule.new(name: "allow", head: head, body: body)]
      end

      it "binds nested patterns" do
        result = evaluator.evaluate

        expect(result.success?).to be(true)
        expect(result.value.to_ruby["allow"]).to be(true)
      end

      it "does not leak bindings when destructuring fails" do
        failing_rule = Ruby::Rego::AST::Rule.new(
          name: "deny",
          head: { type: :complete, name: "deny", location: nil },
          body: [
            Ruby::Rego::AST::QueryLiteral.new(expression: Ruby::Rego::AST::BinaryOp.new(
              operator: :assign,
              left: Ruby::Rego::AST::ArrayLiteral.new(
                elements: [
                  Ruby::Rego::AST::Variable.new(name: "x"),
                  Ruby::Rego::AST::Variable.new(name: "y")
                ]
              ),
              right: Ruby::Rego::AST::Reference.new(
                base: Ruby::Rego::AST::Variable.new(name: "input"),
                path: [Ruby::Rego::AST::DotRefArg.new(value: "roles")]
              )
            )),
            Ruby::Rego::AST::QueryLiteral.new(expression: Ruby::Rego::AST::BinaryOp.new(
              operator: :eq,
              left: Ruby::Rego::AST::Variable.new(name: "x"),
              right: Ruby::Rego::AST::StringLiteral.new(value: "guest")
            ))
          ]
        )

        failing_module = Ruby::Rego::CompiledModule.new(
          package_path: package.path,
          rules_by_name: Ruby::Rego::Compiler.new.index_rules([failing_rule]),
          imports: []
        )
        evaluator_with_failure = described_class.new(failing_module, input: input, data: data)

        evaluator_with_failure.evaluate

        expect(evaluator_with_failure.environment.lookup("x")).to be_a(Ruby::Rego::UndefinedValue)
        expect(evaluator_with_failure.environment.lookup("y")).to be_a(Ruby::Rego::UndefinedValue)
      end
    end

    context "when evaluating multi-literal queries" do
      let(:rules) do
        user_match = Ruby::Rego::AST::BinaryOp.new(
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
        enabled_ref = Ruby::Rego::AST::Reference.new(
          base: Ruby::Rego::AST::Variable.new(name: "data"),
          path: [
            Ruby::Rego::AST::DotRefArg.new(value: "config"),
            Ruby::Rego::AST::DotRefArg.new(value: "enabled")
          ]
        )
        body = [
          Ruby::Rego::AST::QueryLiteral.new(expression: user_match),
          Ruby::Rego::AST::QueryLiteral.new(expression: enabled_ref)
        ]
        head = { type: :complete, name: "allow", location: nil }

        [Ruby::Rego::AST::Rule.new(name: "allow", head: head, body: body)]
      end

      it "requires all literals to succeed" do
        result = evaluator.evaluate

        expect(result.success?).to be(true)
        expect(result.value.to_ruby["allow"]).to be(true)
      end
    end

    context "when using some declarations without collections" do
      let(:rules) do
        some_decl = Ruby::Rego::AST::SomeDecl.new(
          variables: [
            Ruby::Rego::AST::Variable.new(name: "x"),
            Ruby::Rego::AST::Variable.new(name: "y")
          ]
        )
        x_condition = Ruby::Rego::AST::BinaryOp.new(
          operator: :unify,
          left: Ruby::Rego::AST::Variable.new(name: "x"),
          right: Ruby::Rego::AST::NumberLiteral.new(value: 1)
        )
        y_condition = Ruby::Rego::AST::BinaryOp.new(
          operator: :unify,
          left: Ruby::Rego::AST::Variable.new(name: "y"),
          right: Ruby::Rego::AST::NumberLiteral.new(value: 2)
        )
        body = [
          some_decl,
          Ruby::Rego::AST::QueryLiteral.new(expression: x_condition),
          Ruby::Rego::AST::QueryLiteral.new(expression: y_condition)
        ]
        head = { type: :complete, name: "allow", location: nil }

        [Ruby::Rego::AST::Rule.new(name: "allow", head: head, body: body)]
      end

      it "introduces variables for later bindings" do
        result = evaluator.evaluate

        expect(result.success?).to be(true)
        expect(result.value.to_ruby["allow"]).to be(true)
      end
    end

    context "when using not expressions" do
      let(:rules) do
        blocked_ref = Ruby::Rego::AST::Reference.new(
          base: Ruby::Rego::AST::Variable.new(name: "input"),
          path: [Ruby::Rego::AST::DotRefArg.new(value: "blocked")]
        )
        negated = Ruby::Rego::AST::UnaryOp.new(operator: :not, operand: blocked_ref)
        body = [Ruby::Rego::AST::QueryLiteral.new(expression: negated)]
        head = { type: :complete, name: "allow", location: nil }

        [Ruby::Rego::AST::Rule.new(name: "allow", head: head, body: body)]
      end

      it "succeeds when the negated expression fails" do
        result = evaluator.evaluate

        expect(result.success?).to be(true)
        expect(result.value.to_ruby["allow"]).to be(true)
      end
    end

    context "when negation references unbound variables" do
      let(:rules) do
        unbound_check = Ruby::Rego::AST::BinaryOp.new(
          operator: :eq,
          left: Ruby::Rego::AST::Variable.new(name: "x"),
          right: Ruby::Rego::AST::NumberLiteral.new(value: 1)
        )
        negated = Ruby::Rego::AST::UnaryOp.new(operator: :not, operand: unbound_check)
        body = [Ruby::Rego::AST::QueryLiteral.new(expression: negated)]
        head = { type: :complete, name: "allow", location: nil }

        [Ruby::Rego::AST::Rule.new(name: "allow", head: head, body: body)]
      end

      it "raises a safety error" do
        expect { evaluator.evaluate }
          .to raise_error(Ruby::Rego::EvaluationError, /Unsafe negation/)
      end
    end

    context "when combining some and not in a query" do
      let(:rules) do
        roles_ref = Ruby::Rego::AST::Reference.new(
          base: Ruby::Rego::AST::Variable.new(name: "input"),
          path: [Ruby::Rego::AST::DotRefArg.new(value: "roles")]
        )
        some_decl = Ruby::Rego::AST::SomeDecl.new(
          variables: [Ruby::Rego::AST::Variable.new(name: "role")],
          collection: roles_ref
        )
        role_match = Ruby::Rego::AST::BinaryOp.new(
          operator: :unify,
          left: Ruby::Rego::AST::Variable.new(name: "role"),
          right: Ruby::Rego::AST::StringLiteral.new(value: "admin")
        )
        not_guest = Ruby::Rego::AST::UnaryOp.new(
          operator: :not,
          operand: Ruby::Rego::AST::BinaryOp.new(
            operator: :eq,
            left: Ruby::Rego::AST::Variable.new(name: "role"),
            right: Ruby::Rego::AST::StringLiteral.new(value: "guest")
          )
        )
        body = [
          some_decl,
          Ruby::Rego::AST::QueryLiteral.new(expression: role_match),
          Ruby::Rego::AST::QueryLiteral.new(expression: not_guest)
        ]
        head = { type: :complete, name: "allow", location: nil }

        [Ruby::Rego::AST::Rule.new(name: "allow", head: head, body: body)]
      end

      it "threads bindings through nested literals" do
        result = evaluator.evaluate

        expect(result.success?).to be(true)
        expect(result.value.to_ruby["allow"]).to be(true)
      end
    end
  end
end

# rubocop:enable Metrics/BlockLength
