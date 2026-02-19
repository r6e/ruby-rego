# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Evaluator do
  let(:package) { Ruby::Rego::AST::Package.new(path: ["example"]) }

  def evaluator_for(rules, input: {}, data: {})
    rules_by_name = Ruby::Rego::Compiler.new.index_rules(rules)
    compiled_module = Ruby::Rego::CompiledModule.new(
      package_path: package.path,
      rules_by_name: rules_by_name,
      imports: []
    )
    described_class.new(compiled_module, input: input, data: data)
  end

  def complete_rule(body)
    Ruby::Rego::AST::Rule.new(
      name: "allow",
      head: { type: :complete, name: "allow", value: nil, location: nil },
      body: body,
      location: nil
    )
  end

  def complete_value_rule(name, value, body: [])
    Ruby::Rego::AST::Rule.new(
      name: name,
      head: { type: :complete, name: name, value: value, location: nil },
      body: body,
      location: nil
    )
  end

  def function_rule(name, arg_names:, value:, body: [])
    args = arg_names.map { |arg_name| Ruby::Rego::AST::Variable.new(name: arg_name) }
    Ruby::Rego::AST::Rule.new(
      name: name,
      head: { type: :function, name: name, args: args, value: value, location: nil },
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

  def call_reference(base, *segments, args:)
    Ruby::Rego::AST::Call.new(name: ref(base, *segments), args: args)
  end

  def variable(name)
    Ruby::Rego::AST::Variable.new(name: name)
  end

  def array(*elements)
    Ruby::Rego::AST::ArrayLiteral.new(elements: elements)
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

    it "supports user-defined function targets" do
      x = variable("x")
      f_rule = function_rule("f", arg_names: ["x"], value: call("count", [x]))
      g_rule = function_rule("g", arg_names: ["x"], value: call("sum", [x]))

      numbers = array(number(1), number(2), number(3))
      expression = eq(call("f", [numbers]), number(6))
      modifiers = [modifier(variable("f"), variable("g"))]
      allow_rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([allow_rule, f_rule, g_rule])
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "supports literal value replacements for function targets" do
      x = variable("x")
      f_rule = function_rule("f", arg_names: ["x"], value: call("count", [x]))

      numbers = array(number(1), number(2), number(3))
      expression = eq(call("f", [numbers]), string("ok"))
      modifiers = [modifier(variable("f"), string("ok"))]
      allow_rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([allow_rule, f_rule])
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "supports rule-value replacements for function targets" do
      x = variable("x")
      f_rule = function_rule("f", arg_names: ["x"], value: call("count", [x]))
      replacement_rule = complete_value_rule("replacement", string("ok"))

      numbers = array(number(1), number(2), number(3))
      expression = eq(call("f", [numbers]), string("ok"))
      modifiers = [modifier(variable("f"), variable("replacement"))]
      allow_rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([allow_rule, f_rule, replacement_rule])
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "applies with modifiers while evaluating referenced rules" do
      input_ref = ref("input", "user")
      is_admin_rule = complete_value_rule(
        "is_admin",
        boolean(true),
        body: [Ruby::Rego::AST::QueryLiteral.new(expression: eq(input_ref, string("bob")))]
      )

      allow_expression = ref("data", "example", "is_admin")
      allow_modifiers = [modifier(input_ref, string("bob"))]
      allow_rule = complete_rule([literal_with(allow_expression, allow_modifiers)])

      evaluator = evaluator_for([allow_rule, is_admin_rule], input: { "user" => "admin" })
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "supports reference-style builtin override names" do
      registry = Ruby::Rego::Builtins::BuiltinRegistry.instance
      suffix = "#{Process.pid}.#{rand(1_000_000)}"
      count_name = "mock.count_#{suffix}"
      sum_name = "mock.sum_#{suffix}"
      registry.register(count_name, 1) { |items| items.to_ruby.length } unless registry.registered?(count_name)
      registry.register(sum_name, 1) { |items| items.to_ruby.sum } unless registry.registered?(sum_name)

      numbers = array(number(1), number(2), number(3))
      expression = eq(call_reference("mock", "count_#{suffix}", args: [numbers]), number(6))
      modifiers = [modifier(ref("mock", "count_#{suffix}"), ref("mock", "sum_#{suffix}"))]
      rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([rule])
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "applies with modifiers through comprehension evaluation" do
      input_ref = ref("input", "user")
      users_comprehension = Ruby::Rego::AST::ArrayComprehension.new(
        term: input_ref,
        body: [Ruby::Rego::AST::QueryLiteral.new(expression: eq(input_ref, string("bob")))]
      )
      users_rule = complete_value_rule("users", users_comprehension)

      allow_expression = eq(call("count", [ref("data", "example", "users")]), number(1))
      allow_modifiers = [modifier(input_ref, string("bob"))]
      allow_rule = complete_rule([literal_with(allow_expression, allow_modifiers)])

      evaluator = evaluator_for([allow_rule, users_rule], input: { "user" => "admin" })
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "keeps memoization scoped between with and non-with literals" do
      score_rule = complete_value_rule("score", call("count", [array(number(1), number(2), number(3))]))
      score_ref = ref("data", "example", "score")

      body = [
        Ruby::Rego::AST::QueryLiteral.new(expression: eq(score_ref, number(3))),
        literal_with(
          eq(score_ref, number(6)),
          [modifier(variable("count"), variable("sum"))]
        ),
        Ruby::Rego::AST::QueryLiteral.new(expression: eq(score_ref, number(3)))
      ]

      rule = complete_rule(body)
      evaluator = evaluator_for([rule, score_rule])
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "gives precedence to later with modifiers" do
      input_ref = ref("input", "user")
      expression = eq(input_ref, string("carol"))
      modifiers = [
        modifier(input_ref, string("alice")),
        modifier(input_ref, string("carol"))
      ]
      rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([rule], input: { "user" => "admin" })
      result = evaluator.evaluate

      expect(result.value.to_ruby["allow"]).to be(true)
    end

    it "supports nested with scopes with inner multiple overrides" do
      input_ref = ref("input", "user")
      inner_literal = literal_with(
        eq(input_ref, string("carol")),
        [
          modifier(input_ref, string("alice")),
          modifier(input_ref, string("carol"))
        ]
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

    it "returns undefined when with path key is undefined" do
      missing_key = Ruby::Rego::AST::Variable.new(name: "missing")
      input_ref = bracket_ref("input", missing_key)
      expression = eq(input_ref, string("value"))
      modifiers = [modifier(input_ref, string("value"))]
      rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([rule], input: {})

      result = evaluator.evaluate

      expect(result.value.to_ruby).not_to have_key("allow")
    end

    it "raises when overriding an unknown builtin" do
      expression = eq(string("ok"), string("ok"))
      modifiers = [modifier(Ruby::Rego::AST::Variable.new(name: "nope"), Ruby::Rego::AST::Variable.new(name: "count"))]
      rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([rule])

      expect { evaluator.evaluate }.to raise_error(Ruby::Rego::EvaluationError, /Undefined built-in function: nope/)
    end

    it "raises when replacement variable is unsafe" do
      numbers = array(number(1), number(2), number(3))
      expression = eq(call("count", [numbers]), number(3))
      modifiers = [modifier(variable("count"), variable("nope"))]
      rule = complete_rule([literal_with(expression, modifiers)])

      evaluator = evaluator_for([rule])

      expect { evaluator.evaluate }.to raise_error(
        Ruby::Rego::EvaluationError,
        /Unsafe with replacement variable: nope/
      )
    end

    it "treats assignment with undefined replacement rule as undefined" do
      replacement_rule = complete_value_rule(
        "replacement",
        number(0),
        body: [Ruby::Rego::AST::QueryLiteral.new(expression: boolean(false))]
      )

      assignment = Ruby::Rego::AST::BinaryOp.new(
        operator: :assign,
        left: variable("y"),
        right: call("count", [array(number(1), number(2), number(3))])
      )
      modifiers = [modifier(variable("count"), variable("replacement"))]
      allow_rule = complete_value_rule("allow", boolean(true), body: [literal_with(assignment, modifiers)])

      evaluator = evaluator_for([allow_rule, replacement_rule])
      result = evaluator.evaluate

      expect(result.value.to_ruby).not_to have_key("allow")
    end
  end
end

# rubocop:enable Metrics/BlockLength
