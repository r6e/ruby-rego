# frozen_string_literal: true

RSpec.describe Ruby::Rego::AST::Base do
  let(:location) { Ruby::Rego::Location.new(line: 1, column: 2) }

  it "exposes the location" do
    node = described_class.new(location: location)

    expect(node.location).to eq(location)
  end

  it "accepts a visitor" do
    node = described_class.new(location: location)
    visitor = instance_double("Visitor", visit: :result)

    expect(node.accept(visitor)).to eq(:result)
  end
end

RSpec.describe Ruby::Rego::AST::Base do
  let(:location) { Ruby::Rego::Location.new(line: 1, column: 2) }

  it "formats a debug string" do
    node = described_class.new(location: location)

    expect(node.to_s).to include("Ruby::Rego::AST::Base(")
    expect(node.to_s).to include("location=")
  end

  it "compares structural equality" do
    node = described_class.new(location: location)
    same = described_class.new(location: location)
    different = described_class.new(location: nil)

    expect(node == same).to be(true)
    expect(node == different).to be(false)
    expect(node == "other").to be(false)
  end

  it "supports eql? and hash" do
    node = described_class.new(location: location)
    same = described_class.new(location: location)

    expect(node.eql?(same)).to be(true)
    expect(node.hash).to eq(same.hash)
  end
end

RSpec.describe Ruby::Rego::AST::Module do
  let(:package) { Ruby::Rego::AST::Package.new(path: %w[example policy]) }
  let(:imports) { [Ruby::Rego::AST::Import.new(path: "data.users", alias_name: "users")] }
  let(:rules) { [Ruby::Rego::AST::Rule.new(name: "allow", head: { type: :complete }, body: [])] }

  it "exposes package, imports, and rules" do
    node = described_class.new(package: package, imports: imports, rules: rules)

    expect(node.package).to eq(package)
    expect(node.imports).to eq(imports)
    expect(node.rules).to eq(rules)
  end
end

RSpec.describe Ruby::Rego::AST::Package do
  it "stores the package path" do
    node = described_class.new(path: %w[example api])

    expect(node.path).to eq(%w[example api])
  end
end

RSpec.describe Ruby::Rego::AST::Import do
  it "stores the import path and alias" do
    node = described_class.new(path: "data.users", alias_name: "users")

    expect(node.path).to eq("data.users")
    expect(node.alias).to eq("users")
    expect(node.alias_name).to eq("users")
  end

  it "defaults alias to nil" do
    node = described_class.new(path: "data.users")

    expect(node.alias).to be_nil
    expect(node.alias_name).to be_nil
  end
end

RSpec.describe Ruby::Rego::AST::Rule do
  it "exposes rule attributes" do
    node = described_class.new(
      name: "allow",
      head: { type: :complete },
      body: ["input.user"],
      default_value: false,
      else_clause: :else_branch
    )

    expect(node.name).to eq("allow")
    expect(node.head).to eq(type: :complete)
    expect(node.body).to eq(["input.user"])
    expect(node.default_value).to be(false)
    expect(node.else_clause).to eq(:else_branch)
  end
end

RSpec.describe Ruby::Rego::AST::Rule do
  it "detects a complete rule" do
    node = described_class.new(name: "allow", head: { type: :complete }, body: [])

    expect(node.complete?).to be(true)
    expect(node.partial_set?).to be(false)
    expect(node.partial_object?).to be(false)
    expect(node.function?).to be(false)
  end
end

RSpec.describe Ruby::Rego::AST::Rule do
  it "detects partial set and object rules" do
    set_rule = described_class.new(name: "allow", head: { type: :partial_set }, body: [])
    object_rule = described_class.new(name: "allow", head: { type: :partial_object }, body: [])

    expect(set_rule.partial_set?).to be(true)
    expect(object_rule.partial_object?).to be(true)
  end

  it "detects function rules from string types" do
    head = Struct.new(:rule_type).new("function")
    node = described_class.new(name: "allow", head: head, body: [])

    expect(node.function?).to be(true)
  end

  it "returns false when rule type is unknown" do
    node = described_class.new(name: "allow", head: { type: :unknown }, body: [])

    expect(node.complete?).to be(false)
    expect(node.partial_set?).to be(false)
    expect(node.partial_object?).to be(false)
    expect(node.function?).to be(false)
  end
end

RSpec.describe Ruby::Rego::AST::Literal do
  it "stores a literal value" do
    node = described_class.new(value: "hello")

    expect(node.value).to eq("hello")
  end
end

RSpec.describe Ruby::Rego::AST::StringLiteral do
  it "stores a string literal" do
    node = described_class.new(value: "hello")

    expect(node.value).to eq("hello")
  end
end

RSpec.describe Ruby::Rego::AST::NumberLiteral do
  it "stores a numeric literal" do
    node = described_class.new(value: 42)

    expect(node.value).to eq(42)
  end
end

RSpec.describe Ruby::Rego::AST::BooleanLiteral do
  it "stores a boolean literal" do
    node = described_class.new(value: true)

    expect(node.value).to be(true)
  end
end

RSpec.describe Ruby::Rego::AST::NullLiteral do
  it "stores a null literal" do
    node = described_class.new

    expect(node.value).to be_nil
  end
end

RSpec.describe Ruby::Rego::AST::Variable do
  it "stores a variable name" do
    node = described_class.new(name: "user")

    expect(node.name).to eq("user")
  end
end

RSpec.describe Ruby::Rego::AST::RefArg do
  it "stores a reference argument value" do
    node = described_class.new(value: "roles")

    expect(node.value).to eq("roles")
  end
end

RSpec.describe Ruby::Rego::AST::DotRefArg do
  it "stores a dot reference argument" do
    node = described_class.new(value: "roles")

    expect(node.value).to eq("roles")
  end
end

RSpec.describe Ruby::Rego::AST::BracketRefArg do
  it "stores a bracket reference argument" do
    node = described_class.new(value: 0)

    expect(node.value).to eq(0)
  end
end

RSpec.describe Ruby::Rego::AST::Reference do
  it "stores a base and path" do
    base = Ruby::Rego::AST::Variable.new(name: "input")
    path = [
      Ruby::Rego::AST::DotRefArg.new(value: "user"),
      Ruby::Rego::AST::BracketRefArg.new(value: 0)
    ]

    node = described_class.new(base: base, path: path)

    expect(node.base).to eq(base)
    expect(node.path).to eq(path)
  end
end

RSpec.describe Ruby::Rego::AST::BinaryOp do
  it "stores an operator and operands" do
    left = Ruby::Rego::AST::Variable.new(name: "x")
    right = Ruby::Rego::AST::NumberLiteral.new(value: 1)

    node = described_class.new(operator: :eq, left: left, right: right)

    expect(node.operator).to eq(:eq)
    expect(node.left).to eq(left)
    expect(node.right).to eq(right)
  end

  it "rejects unsupported operators" do
    left = Ruby::Rego::AST::Variable.new(name: "x")
    right = Ruby::Rego::AST::NumberLiteral.new(value: 1)

    expect do
      described_class.new(operator: :unknown, left: left, right: right)
    end.to raise_error(ArgumentError, /Unknown binary operator/)
  end
end

RSpec.describe Ruby::Rego::AST::UnaryOp do
  it "stores an operator and operand" do
    operand = Ruby::Rego::AST::Variable.new(name: "enabled")

    node = described_class.new(operator: :not, operand: operand)

    expect(node.operator).to eq(:not)
    expect(node.operand).to eq(operand)
  end

  it "rejects unsupported operators" do
    operand = Ruby::Rego::AST::Variable.new(name: "enabled")

    expect do
      described_class.new(operator: :unknown, operand: operand)
    end.to raise_error(ArgumentError, /Unknown unary operator/)
  end
end

RSpec.describe Ruby::Rego::AST::ArrayLiteral do
  it "stores array elements" do
    elements = [Ruby::Rego::AST::NumberLiteral.new(value: 1)]

    node = described_class.new(elements: elements)

    expect(node.elements).to eq(elements)
  end
end

RSpec.describe Ruby::Rego::AST::ObjectLiteral do
  it "stores object pairs" do
    key = Ruby::Rego::AST::StringLiteral.new(value: "role")
    value = Ruby::Rego::AST::StringLiteral.new(value: "admin")
    pairs = [[key, value]]

    node = described_class.new(pairs: pairs)

    expect(node.pairs).to eq(pairs)
  end
end

RSpec.describe Ruby::Rego::AST::SetLiteral do
  it "stores set elements" do
    elements = [Ruby::Rego::AST::StringLiteral.new(value: "admin")]

    node = described_class.new(elements: elements)

    expect(node.elements).to eq(elements)
  end
end

RSpec.describe Ruby::Rego::AST::ArrayComprehension do
  it "stores a term and body" do
    term = Ruby::Rego::AST::Variable.new(name: "x")
    body = [Ruby::Rego::AST::BinaryOp.new(operator: :eq, left: term, right: term)]

    node = described_class.new(term: term, body: body)

    expect(node.term).to eq(term)
    expect(node.body).to eq(body)
  end
end

RSpec.describe Ruby::Rego::AST::ObjectComprehension do
  it "stores a term and body" do
    term = Ruby::Rego::AST::StringLiteral.new(value: "key")
    body = [Ruby::Rego::AST::Variable.new(name: "v")]

    node = described_class.new(term: term, body: body)

    expect(node.term).to eq(term)
    expect(node.body).to eq(body)
  end
end

RSpec.describe Ruby::Rego::AST::SetComprehension do
  it "stores a term and body" do
    term = Ruby::Rego::AST::Variable.new(name: "item")
    body = [Ruby::Rego::AST::Variable.new(name: "item")]

    node = described_class.new(term: term, body: body)

    expect(node.term).to eq(term)
    expect(node.body).to eq(body)
  end
end

RSpec.describe Ruby::Rego::AST::Call do
  it "stores a name and arguments" do
    args = [Ruby::Rego::AST::Variable.new(name: "items")]

    node = described_class.new(name: "count", args: args)

    expect(node.name).to eq("count")
    expect(node.args).to eq(args)
  end
end
