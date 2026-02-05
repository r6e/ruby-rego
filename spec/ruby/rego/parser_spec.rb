# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Parser do
  def parse(source)
    tokens = Ruby::Rego::Lexer.new(source).tokenize
    described_class.new(tokens).parse
  end

  def parse_expression(source)
    tokens = Ruby::Rego::Lexer.new(source).tokenize
    described_class.new(tokens).send(:parse_expression)
  end

  def parse_rule(source)
    parse("package example\n#{source}").rules.first
  end

  describe "#parse" do
    it "parses package declarations" do
      module_node = parse("package example.policy")

      expect(module_node).to be_a(Ruby::Rego::AST::Module)
      expect(module_node.package.path).to eq(%w[example policy])
      expect(module_node.imports).to eq([])
      expect(module_node.rules).to eq([])
    end

    it "parses imports with optional aliases" do
      source = <<~REGO
        package example.auth
        import data.users as users
        import input
      REGO
      module_node = parse(source)

      expect(module_node.imports.length).to eq(2)
      expect(module_node.imports[0].path).to eq("data.users")
      expect(module_node.imports[0].alias_name).to eq("users")
      expect(module_node.imports[1].path).to eq("input")
      expect(module_node.imports[1].alias_name).to be_nil
    end

    it "parses multiple unbraced rules separated by newlines" do
      source = <<~REGO
        package example
        allow if input.x;
        deny if input.y
      REGO

      module_node = parse(source)

      expect(module_node.rules.map(&:name)).to eq(%w[allow deny])
    end

    it "raises when a rule has no body or value" do
      source = <<~REGO
        package example
        allow
      REGO

      expect { parse(source) }.to raise_error(Ruby::Rego::ParserError, /Expected rule body or value/)
    end

    it "parses complete rules with constants" do
      rule = parse_rule("allow := true")

      expect(rule.name).to eq("allow")
      expect(rule.head[:type]).to eq(:complete)
      expect(rule.head[:value]).to be_a(Ruby::Rego::AST::BooleanLiteral)
      expect(rule.body).to be_nil
    end

    it "parses conditional rules with bodies" do
      rule = parse_rule("allow if input.user == \"admin\"; input.enabled")

      expect(rule.body.length).to eq(2)
      expect(rule.body[0]).to be_a(Ruby::Rego::AST::QueryLiteral)
      expect(rule.body[0].expression).to be_a(Ruby::Rego::AST::BinaryOp)
      expect(rule.body[1].expression).to be_a(Ruby::Rego::AST::Reference)
    end

    it "parses partial set rules" do
      rule = parse_rule("roles contains \"admin\"")

      expect(rule.head[:type]).to eq(:partial_set)
      expect(rule.head[:term]).to be_a(Ruby::Rego::AST::StringLiteral)
    end

    it "parses partial object rules" do
      rule = parse_rule("users[\"alice\"] := {\"role\": \"admin\"}")

      expect(rule.head[:type]).to eq(:partial_object)
      expect(rule.head[:key]).to be_a(Ruby::Rego::AST::StringLiteral)
      expect(rule.head[:value]).to be_a(Ruby::Rego::AST::ObjectLiteral)
    end

    it "parses function rules with parameters" do
      rule = parse_rule("sum(x, y) := x + y")

      expect(rule.head[:type]).to eq(:function)
      expect(rule.head[:args].length).to eq(2)
      expect(rule.head[:value]).to be_a(Ruby::Rego::AST::BinaryOp)
    end

    it "parses default rules" do
      rule = parse_rule("default allow := false")

      expect(rule.default_value).to be_a(Ruby::Rego::AST::BooleanLiteral)
      expect(rule.default_value.value).to be(false)
    end

    it "raises when default rules have else clauses" do
      source = <<~REGO
        package example
        default allow := false else := true
      REGO

      expect { parse(source) }.to raise_error(Ruby::Rego::ParserError, /Default rules cannot have else clauses/)
    end

    it "parses else clauses" do
      rule = parse_rule("allow := true else := false")

      expect(rule.else_clause).to be_a(Hash)
      expect(rule.else_clause[:value]).to be_a(Ruby::Rego::AST::BooleanLiteral)
    end

    it "parses else clauses after a newline" do
      rule = parse_rule("allow { input.user == \"admin\" }\nelse := false")

      expect(rule.else_clause).to be_a(Hash)
      expect(rule.else_clause[:value]).to be_a(Ruby::Rego::AST::BooleanLiteral)
      expect(rule.else_clause[:value].value).to be(false)
    end

    it "parses some, not, and with literals" do
      rule = parse_rule("allow { some x; not input.blocked; input.user == \"admin\" with input.user as \"bob\" }")

      expect(rule.body[0]).to be_a(Ruby::Rego::AST::SomeDecl)
      expect(rule.body[1]).to be_a(Ruby::Rego::AST::QueryLiteral)
      expect(rule.body[1].expression).to be_a(Ruby::Rego::AST::UnaryOp)
      expect(rule.body[2].with_modifiers.length).to eq(1)
    end
  end

  describe "#parse_expression" do
    it "parses literal types" do
      string_literal = parse_expression("\"hello\\nworld\"")
      raw_literal = parse_expression("`raw {value}`")
      number_literal = parse_expression("42")
      float_literal = parse_expression("3.14")
      sci_literal = parse_expression("1e-3")
      true_literal = parse_expression("true")
      false_literal = parse_expression("false")
      null_literal = parse_expression("null")

      expect(string_literal).to be_a(Ruby::Rego::AST::StringLiteral)
      expect(string_literal.value).to eq("hello\nworld")
      expect(raw_literal).to be_a(Ruby::Rego::AST::StringLiteral)
      expect(raw_literal.value).to eq("raw {value}")
      expect(number_literal).to be_a(Ruby::Rego::AST::NumberLiteral)
      expect(number_literal.value).to eq(42)
      expect(float_literal.value).to eq(3.14)
      expect(sci_literal.value).to be_within(1.0e-10).of(1.0e-3)
      expect(true_literal).to be_a(Ruby::Rego::AST::BooleanLiteral)
      expect(true_literal.value).to eq(true)
      expect(false_literal).to be_a(Ruby::Rego::AST::BooleanLiteral)
      expect(false_literal.value).to eq(false)
      expect(null_literal).to be_a(Ruby::Rego::AST::NullLiteral)
      expect(null_literal.value).to be_nil
    end

    it "parses unary expressions" do
      not_expr = parse_expression("not true")
      neg_expr = parse_expression("-1")

      expect(not_expr).to be_a(Ruby::Rego::AST::UnaryOp)
      expect(not_expr.operator).to eq(:not)
      expect(not_expr.operand).to be_a(Ruby::Rego::AST::BooleanLiteral)

      expect(neg_expr).to be_a(Ruby::Rego::AST::UnaryOp)
      expect(neg_expr.operator).to eq(:minus)
      expect(neg_expr.operand).to be_a(Ruby::Rego::AST::NumberLiteral)
    end

    it "parses binary operations with precedence" do
      expr = parse_expression("1 + 2 * 3")

      expect(expr).to be_a(Ruby::Rego::AST::BinaryOp)
      expect(expr.operator).to eq(:plus)
      expect(expr.left).to be_a(Ruby::Rego::AST::NumberLiteral)
      expect(expr.right).to be_a(Ruby::Rego::AST::BinaryOp)
      expect(expr.right.operator).to eq(:mult)
    end

    it "parses nested expressions with parentheses" do
      expr = parse_expression("(1 + 2) * (3 - 4)")

      expect(expr).to be_a(Ruby::Rego::AST::BinaryOp)
      expect(expr.operator).to eq(:mult)
      expect(expr.left.operator).to eq(:plus)
      expect(expr.right.operator).to eq(:minus)
    end

    it "parses references with dot and bracket notation" do
      expr = parse_expression("input.user.roles[0]")

      expect(expr).to be_a(Ruby::Rego::AST::Reference)
      expect(expr.base).to be_a(Ruby::Rego::AST::Variable)
      expect(expr.base.name).to eq("input")
      expect(expr.path.length).to eq(3)
      expect(expr.path[0]).to be_a(Ruby::Rego::AST::DotRefArg)
      expect(expr.path[0].value).to eq("user")
      expect(expr.path[1]).to be_a(Ruby::Rego::AST::DotRefArg)
      expect(expr.path[1].value).to eq("roles")
      expect(expr.path[2]).to be_a(Ruby::Rego::AST::BracketRefArg)
      expect(expr.path[2].value).to be_a(Ruby::Rego::AST::NumberLiteral)
    end

    it "parses composite literals" do
      array = parse_expression("[1, true, \"a\"]")
      object = parse_expression("{\"a\": 1, \"b\": 2}")
      set = parse_expression("{1, 2, 3}")
      empty_set = parse_expression("{}")

      expect(array).to be_a(Ruby::Rego::AST::ArrayLiteral)
      expect(array.elements.length).to eq(3)

      expect(object).to be_a(Ruby::Rego::AST::ObjectLiteral)
      expect(object.pairs.length).to eq(2)
      expect(object.pairs[0][0]).to be_a(Ruby::Rego::AST::StringLiteral)

      expect(set).to be_a(Ruby::Rego::AST::SetLiteral)
      expect(set.elements.length).to eq(3)

      expect(empty_set).to be_a(Ruby::Rego::AST::SetLiteral)
      expect(empty_set.elements).to eq([])
    end

    it "parses function calls" do
      expr = parse_expression("count([1, 2])")

      expect(expr).to be_a(Ruby::Rego::AST::Call)
      expect(expr.name).to be_a(Ruby::Rego::AST::Variable)
      expect(expr.name.name).to eq("count")
      expect(expr.args.length).to eq(1)
      expect(expr.args.first).to be_a(Ruby::Rego::AST::ArrayLiteral)
    end

    it "parses comprehensions" do
      array = parse_expression("[x | x > 1]")
      object = parse_expression("{x: y | x > 1}")
      set = parse_expression("{x | x > 1}")

      expect(array).to be_a(Ruby::Rego::AST::ArrayComprehension)
      expect(array.term).to be_a(Ruby::Rego::AST::Variable)
      expect(array.body.length).to eq(1)

      expect(object).to be_a(Ruby::Rego::AST::ObjectComprehension)
      expect(object.term).to be_a(Array)

      expect(set).to be_a(Ruby::Rego::AST::SetComprehension)
      expect(set.term).to be_a(Ruby::Rego::AST::Variable)
    end

    it "parses multiline arrays and sets with trailing newlines" do
      array = parse_expression("[1, 2\n]")
      set = parse_expression("{1, 2\n}")

      expect(array).to be_a(Ruby::Rego::AST::ArrayLiteral)
      expect(array.elements.length).to eq(2)

      expect(set).to be_a(Ruby::Rego::AST::SetLiteral)
      expect(set.elements.length).to eq(2)
    end

    it "parses multiline calls and parenthesized expressions" do
      call = parse_expression("count(\n  [1, 2]\n)")
      wrapped = parse_expression("(\n  input.user\n)")
      object = parse_expression("{\n  \"a\": 1\n}\n")

      expect(call).to be_a(Ruby::Rego::AST::Call)
      expect(wrapped).to be_a(Ruby::Rego::AST::Reference)
      expect(object).to be_a(Ruby::Rego::AST::ObjectLiteral)
    end
  end
end

# rubocop:enable Metrics/BlockLength
