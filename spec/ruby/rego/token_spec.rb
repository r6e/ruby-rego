# frozen_string_literal: true

TOKEN_KEYWORDS = %i[
  PACKAGE IMPORT AS DEFAULT IF CONTAINS SOME IN EVERY NOT AND OR WITH ELSE TRUE FALSE NULL DATA INPUT
].freeze
TOKEN_OPERATORS = %i[
  ASSIGN EQ NEQ LT LTE GT GTE PLUS MINUS STAR SLASH PERCENT AND OR PIPE AMPERSAND UNIFY
].freeze
TOKEN_DELIMITERS = %i[
  LPAREN RPAREN LBRACKET RBRACKET LBRACE RBRACE DOT COMMA SEMICOLON COLON UNDERSCORE
].freeze
TOKEN_LITERALS = %i[STRING TEMPLATE_STRING NUMBER RAW_STRING RAW_TEMPLATE_STRING IDENT].freeze
TOKEN_SPECIALS = %i[EOF NEWLINE COMMENT].freeze

RSpec.describe Ruby::Rego::TokenType do
  describe "constants" do
    it "defines keyword constants" do
      TOKEN_KEYWORDS.each { |name| expect(described_class.const_get(name)).to eq(name) }
    end

    it "defines operator constants" do
      TOKEN_OPERATORS.each { |name| expect(described_class.const_get(name)).to eq(name) }
    end

    it "defines delimiter constants" do
      TOKEN_DELIMITERS.each { |name| expect(described_class.const_get(name)).to eq(name) }
    end

    it "defines literal constants" do
      TOKEN_LITERALS.each { |name| expect(described_class.const_get(name)).to eq(name) }
    end

    it "defines special constants" do
      TOKEN_SPECIALS.each { |name| expect(described_class.const_get(name)).to eq(name) }
    end
  end
end

RSpec.describe Ruby::Rego::TokenType do
  describe ".keyword?" do
    it "returns true for keyword types" do
      expect(described_class.keyword?(described_class::PACKAGE)).to be(true)
      expect(described_class.keyword?(described_class::IMPORT)).to be(true)
      expect(described_class.keyword?(described_class::INPUT)).to be(true)
    end

    it "returns false for non-keyword types" do
      expect(described_class.keyword?(described_class::IDENT)).to be(false)
      expect(described_class.keyword?(described_class::EQ)).to be(false)
    end
  end
end

RSpec.describe Ruby::Rego::TokenType do
  describe ".operator?" do
    it "returns true for operator types" do
      expect(described_class.operator?(described_class::ASSIGN)).to be(true)
      expect(described_class.operator?(described_class::NEQ)).to be(true)
    end

    it "returns false for non-operator types" do
      expect(described_class.operator?(described_class::PACKAGE)).to be(false)
      expect(described_class.operator?(described_class::STRING)).to be(false)
    end
  end
end

RSpec.describe Ruby::Rego::TokenType do
  describe ".literal?" do
    it "returns true for literal types" do
      expect(described_class.literal?(described_class::STRING)).to be(true)
      expect(described_class.literal?(described_class::IDENT)).to be(true)
    end

    it "returns false for non-literal types" do
      expect(described_class.literal?(described_class::PACKAGE)).to be(false)
      expect(described_class.literal?(described_class::LPAREN)).to be(false)
    end
  end
end

RSpec.describe Ruby::Rego::Token do
  let(:location) { Ruby::Rego::Location.new(line: 1, column: 2) }

  it "exposes token attributes" do
    token = described_class.new(
      type: Ruby::Rego::TokenType::IDENT,
      value: "allow",
      location: location
    )

    expect(token.type).to eq(Ruby::Rego::TokenType::IDENT)
    expect(token.value).to eq("allow")
    expect(token.location).to eq(location)
  end
end

RSpec.describe Ruby::Rego::Token do
  it "delegates keyword/operator/literal helpers" do
    keyword = described_class.new(type: Ruby::Rego::TokenType::PACKAGE)
    operator = described_class.new(type: Ruby::Rego::TokenType::EQ)
    literal = described_class.new(type: Ruby::Rego::TokenType::NUMBER)

    expect(keyword.keyword?).to be(true)
    expect(keyword.operator?).to be(false)
    expect(keyword.literal?).to be(false)

    expect(operator.keyword?).to be(false)
    expect(operator.operator?).to be(true)
    expect(operator.literal?).to be(false)

    expect(literal.keyword?).to be(false)
    expect(literal.operator?).to be(false)
    expect(literal.literal?).to be(true)
  end
end

RSpec.describe Ruby::Rego::Token do
  let(:location) { Ruby::Rego::Location.new(line: 1, column: 2) }

  describe "#to_s" do
    it "includes type, value, and location" do
      token = described_class.new(
        type: Ruby::Rego::TokenType::IDENT,
        value: "allow",
        location: location
      )

      expect(token.to_s).to eq("Token(type=IDENT, value=\"allow\", location=line 1, column 2)")
    end

    it "omits location when nil" do
      token = described_class.new(type: Ruby::Rego::TokenType::PACKAGE)

      expect(token.to_s).to eq("Token(type=PACKAGE, value=nil)")
    end
  end
end
