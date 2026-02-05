# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Parser do
  def parse(source)
    tokens = Ruby::Rego::Lexer.new(source).tokenize
    described_class.new(tokens).parse
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
end

# rubocop:enable Metrics/BlockLength
