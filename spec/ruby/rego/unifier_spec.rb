# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Unifier do
  let(:environment) { Ruby::Rego::Environment.new }
  let(:unifier) { described_class.new }

  def unify(pattern, value)
    unifier.unify(pattern, value, environment)
  end

  it "binds simple variables" do
    pattern = Ruby::Rego::AST::Variable.new(name: "x")
    results = unify(pattern, Ruby::Rego::Value.from_ruby(10))

    expect(results.size).to eq(1)
    expect(results.first["x"].to_ruby).to eq(10)
  end

  it "matches nested structures" do
    pattern = Ruby::Rego::AST::ArrayLiteral.new(
      elements: [
        Ruby::Rego::AST::Variable.new(name: "x"),
        Ruby::Rego::AST::ObjectLiteral.new(
          pairs: [
            [
              Ruby::Rego::AST::StringLiteral.new(value: "a"),
              Ruby::Rego::AST::Variable.new(name: "y")
            ]
          ]
        )
      ]
    )

    results = unify(pattern, Ruby::Rego::Value.from_ruby([1, { "a" => 2 }]))

    expect(results.size).to eq(1)
    expect(results.first["x"].to_ruby).to eq(1)
    expect(results.first["y"].to_ruby).to eq(2)
  end

  it "matches partial objects" do
    pattern = Ruby::Rego::AST::ObjectLiteral.new(
      pairs: [
        [
          Ruby::Rego::AST::StringLiteral.new(value: "a"),
          Ruby::Rego::AST::Variable.new(name: "x")
        ]
      ]
    )

    results = unify(pattern, { "a" => 1, "b" => 2 })

    expect(results.size).to eq(1)
    expect(results.first["x"].to_ruby).to eq(1)
  end

  it "does not reuse object keys for multiple pairs" do
    pattern = Ruby::Rego::AST::ObjectLiteral.new(
      pairs: [
        [Ruby::Rego::AST::Variable.new(name: "k1"), Ruby::Rego::AST::NumberLiteral.new(value: 1)],
        [Ruby::Rego::AST::Variable.new(name: "k2"), Ruby::Rego::AST::NumberLiteral.new(value: 1)]
      ]
    )

    results = unify(pattern, { "a" => 1 })

    expect(results).to be_empty
  end

  it "does not allow repeated key variables in object patterns" do
    pattern = Ruby::Rego::AST::ObjectLiteral.new(
      pairs: [
        [Ruby::Rego::AST::Variable.new(name: "k"), Ruby::Rego::AST::NumberLiteral.new(value: 1)],
        [Ruby::Rego::AST::Variable.new(name: "k"), Ruby::Rego::AST::NumberLiteral.new(value: 1)]
      ]
    )

    results = unify(pattern, { "a" => 1, "b" => 1 })

    expect(results).to be_empty
  end

  it "does not leak bindings on mismatch" do
    pattern = Ruby::Rego::AST::ArrayLiteral.new(
      elements: [
        Ruby::Rego::AST::Variable.new(name: "x"),
        Ruby::Rego::AST::Variable.new(name: "y")
      ]
    )

    results = unify(pattern, [1])

    expect(results).to be_empty
  end

  it "returns multiple solutions for key matches" do
    pattern = Ruby::Rego::AST::ObjectLiteral.new(
      pairs: [
        [
          Ruby::Rego::AST::Variable.new(name: "key"),
          Ruby::Rego::AST::NumberLiteral.new(value: 1)
        ]
      ]
    )

    results = unify(pattern, { "a" => 1, "b" => 1 })
    keys = results.map { |bindings| bindings["key"].to_ruby }.sort

    expect(keys).to eq(%w[a b])
  end

  it "supports wildcard patterns" do
    pattern = Ruby::Rego::AST::Variable.new(name: "_")
    results = unify(pattern, Ruby::Rego::Value.from_ruby("anything"))

    expect(results).to eq([{}])
  end

  it "fails on mismatched literals" do
    pattern = Ruby::Rego::AST::NumberLiteral.new(value: 1)

    expect(unify(pattern, Ruby::Rego::Value.from_ruby(2))).to be_empty
  end

  it "fails on object key normalization collisions" do
    pattern = Ruby::Rego::AST::ObjectLiteral.new(
      pairs: [
        [
          Ruby::Rego::AST::StringLiteral.new(value: "a"),
          Ruby::Rego::AST::NumberLiteral.new(value: 1)
        ]
      ]
    )

    results = unify(pattern, { "a" => 1, :a => 1 })

    expect(results).to be_empty
  end
end

# rubocop:enable Metrics/BlockLength
