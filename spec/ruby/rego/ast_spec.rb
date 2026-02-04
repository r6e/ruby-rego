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
