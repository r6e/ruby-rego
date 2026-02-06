# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Evaluator do
  let(:package) { Ruby::Rego::AST::Package.new(path: ["example"]) }

  def evaluator_for(rules, input: {}, data: {})
    module_node = Ruby::Rego::AST::Module.new(package: package, imports: [], rules: rules)
    described_class.new(module_node, input: input, data: data)
  end

  def complete_rule(body)
    Ruby::Rego::AST::Rule.new(
      name: "allow",
      head: { type: :complete, name: "allow", value: nil, location: nil },
      body: body,
      location: nil
    )
  end

  def ref(base, *segments)
    Ruby::Rego::AST::Reference.new(
      base: Ruby::Rego::AST::Variable.new(name: base),
      path: segments.map { |segment| Ruby::Rego::AST::DotRefArg.new(value: segment) }
    )
  end

  def bracket_ref(base, segment)
    Ruby::Rego::AST::Reference.new(
      base: Ruby::Rego::AST::Variable.new(name: base),
      path: [Ruby::Rego::AST::BracketRefArg.new(value: segment)]
    )
  end

  def eq(left, right)
    Ruby::Rego::AST::BinaryOp.new(operator: :eq, left: left, right: right)
  end

  def and_op(left, right)
    Ruby::Rego::AST::BinaryOp.new(operator: :and, left: left, right: right)
  end

  def literal_with(expression, modifiers)
    Ruby::Rego::AST::QueryLiteral.new(expression: expression, with_modifiers: modifiers)
  end

  def modifier(target, value)
    Ruby::Rego::AST::WithModifier.new(target: target, value: value)
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

  def call(name, args)
    Ruby::Rego::AST::Call.new(name: Ruby::Rego::AST::Variable.new(name: name), args: args)
  end

  describe "with modifiers" do
    it "mocks input values" do
      input_ref = ref("input", "user", "name")
      expression = eq(input_ref, string("bob"))
      modifiers = [modifier(input_ref, string("bob"))]
      rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([rule], input: { "user" => { "name" => "admin" } })
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "mocks data values" do
      data_ref = ref("data", "config", "enabled")
      expression = eq(data_ref, boolean(true))
      modifiers = [modifier(data_ref, boolean(true))]
      rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([rule], data: { "config" => { "enabled" => false } })
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "handles multiple with clauses" do
      input_ref = ref("input", "user", "name")
      data_ref = ref("data", "config", "enabled")
      expression = and_op(eq(input_ref, string("bob")), eq(data_ref, boolean(true)))
      modifiers = [
        modifier(input_ref, string("bob")),
        modifier(data_ref, boolean(true))
      ]
      rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for(
        [rule],
        input: { "user" => { "name" => "admin" } },
        data: { "config" => { "enabled" => false } }
      )
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "supports nested with scopes" do
      input_ref = ref("input", "user")
      inner_literal = literal_with(
        eq(input_ref, string("alice")),
        [modifier(input_ref, string("alice"))]
      )
      comprehension = Ruby::Rego::AST::ArrayComprehension.new(
        term: number(1),
        body: [inner_literal]
      )
      count_call = call("count", [comprehension])
      expression = and_op(eq(input_ref, string("bob")), eq(count_call, number(1)))
      outer_literal = literal_with(expression, [modifier(input_ref, string("bob"))])
      rule = complete_rule([outer_literal])

      evaluator = evaluator_for([rule], input: { "user" => "admin" })
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "mocks builtin functions" do
      array = Ruby::Rego::AST::ArrayLiteral.new(elements: [number(1), number(2), number(3)])
      count_call = call("count", [array])
      expression = eq(count_call, number(6))
      modifiers = [modifier(Ruby::Rego::AST::Variable.new(name: "count"), Ruby::Rego::AST::Variable.new(name: "sum"))]
      rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([rule])
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "returns undefined when with path key is undefined" do
      missing_key = Ruby::Rego::AST::Variable.new(name: "missing")
      input_ref = bracket_ref("input", missing_key)
      expression = eq(input_ref, string("value"))
      modifiers = [modifier(input_ref, string("value"))]
      rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([rule], input: {})

      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(Ruby::Rego::UndefinedValue::UNDEFINED)
    end

    it "raises when overriding an unknown builtin" do
      expression = eq(string("ok"), string("ok"))
      modifiers = [modifier(Ruby::Rego::AST::Variable.new(name: "nope"), Ruby::Rego::AST::Variable.new(name: "count"))]
      rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([rule])

      expect { evaluator.evaluate }.to raise_error(Ruby::Rego::EvaluationError, /Undefined built-in function: nope/)
    end
  end
end

# rubocop:enable Metrics/BlockLength
