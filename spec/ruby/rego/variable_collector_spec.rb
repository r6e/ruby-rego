# frozen_string_literal: true

module VariableCollectorSpecHelpers
  def ast_var(name)
    Ruby::Rego::AST::Variable.new(name: name)
  end

  def ast_some_decl(name)
    Ruby::Rego::AST::SomeDecl.new(variables: [ast_var(name)])
  end

  def ast_dot_ref(base_name, value)
    Ruby::Rego::AST::Reference.new(
      base: ast_var(base_name),
      path: [Ruby::Rego::AST::DotRefArg.new(value: value)]
    )
  end

  def ast_number(value)
    Ruby::Rego::AST::NumberLiteral.new(value: value)
  end

  def ast_eq(left, right)
    Ruby::Rego::AST::BinaryOp.new(operator: :eq, left: left, right: right)
  end

  def ast_unify(left, right)
    Ruby::Rego::AST::BinaryOp.new(operator: :unify, left: left, right: right)
  end

  def ast_query_literal(expression)
    Ruby::Rego::AST::QueryLiteral.new(expression: expression)
  end

  def local_comprehension
    Ruby::Rego::AST::ArrayComprehension.new(
      term: ast_var("x"),
      body: [
        ast_some_decl("x"),
        ast_query_literal(ast_eq(ast_dot_ref("input", "flag"), ast_number(1)))
      ]
    )
  end

  def nested_comprehension
    inner_comprehension = Ruby::Rego::AST::ArrayComprehension.new(
      term: ast_var("inner"),
      body: [ast_some_decl("inner")]
    )
    unify_expression = ast_unify(inner_comprehension, ast_var("x"))

    Ruby::Rego::AST::ArrayComprehension.new(
      term: ast_var("inner"),
      body: [ast_query_literal(unify_expression)]
    )
  end
end

RSpec.describe Ruby::Rego::Evaluator::VariableCollector do
  include VariableCollectorSpecHelpers

  subject(:collector) { described_class.new }

  it "ignores comprehension-local variables" do
    expect(collector.collect(local_comprehension)).to contain_exactly("input")
  end

  it "does not treat nested comprehension terms as bound" do
    expect(collector.collect(nested_comprehension)).to contain_exactly("inner")
  end
end
