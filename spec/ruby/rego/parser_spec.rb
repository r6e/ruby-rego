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

    it "raises when rule parsing is not implemented" do
      source = <<~REGO
        package example.auth
        allow
      REGO

      expect { parse(source) }.to raise_error(Ruby::Rego::ParserError, /Rule parsing not implemented/)
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
  end
end

# rubocop:enable Metrics/BlockLength
