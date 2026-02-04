# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Lexer do
  def tokenize(source)
    described_class.new(source).tokenize
  end

  describe "#tokenize" do
    it "tokenizes keywords" do
      source = "package import as default if contains some in every not with else true false null data input"
      types = tokenize(source).map(&:type)

      expect(types).to eq(
        [
          Ruby::Rego::TokenType::PACKAGE,
          Ruby::Rego::TokenType::IMPORT,
          Ruby::Rego::TokenType::AS,
          Ruby::Rego::TokenType::DEFAULT,
          Ruby::Rego::TokenType::IF,
          Ruby::Rego::TokenType::CONTAINS,
          Ruby::Rego::TokenType::SOME,
          Ruby::Rego::TokenType::IN,
          Ruby::Rego::TokenType::EVERY,
          Ruby::Rego::TokenType::NOT,
          Ruby::Rego::TokenType::WITH,
          Ruby::Rego::TokenType::ELSE,
          Ruby::Rego::TokenType::TRUE,
          Ruby::Rego::TokenType::FALSE,
          Ruby::Rego::TokenType::NULL,
          Ruby::Rego::TokenType::DATA,
          Ruby::Rego::TokenType::INPUT,
          Ruby::Rego::TokenType::EOF
        ]
      )
    end

    it "tokenizes identifiers and underscores" do
      tokens = tokenize("allow user_name _")

      expect(tokens[0].type).to eq(Ruby::Rego::TokenType::IDENT)
      expect(tokens[0].value).to eq("allow")
      expect(tokens[1].type).to eq(Ruby::Rego::TokenType::IDENT)
      expect(tokens[1].value).to eq("user_name")
      expect(tokens[2].type).to eq(Ruby::Rego::TokenType::UNDERSCORE)
    end

    it "tokenizes numbers including floats and scientific notation" do
      tokens = tokenize("0 12 3.14 6.02e23 1e-3 4E+2")
      values = tokens.select { |token| token.type == Ruby::Rego::TokenType::NUMBER }.map(&:value)

      expect(values[0]).to eq(0)
      expect(values[0]).to be_a(Integer)
      expect(values[1]).to eq(12)
      expect(values[1]).to be_a(Integer)
      expect(values[2]).to eq(3.14)
      expect(values[2]).to be_a(Float)
      expect(values[3]).to be_a(Float)
      expect(values[3]).to be_within(1.0e10).of(6.02e23)
      expect(values[4]).to be_within(1.0e-10).of(1.0e-3)
      expect(values[5]).to be_within(1.0e-6).of(4.0e2)
    end

    it "tokenizes double-quoted strings with escapes" do
      tokens = tokenize("\"hello\\nworld\" \"quote: \\\"\"")

      expect(tokens[0].type).to eq(Ruby::Rego::TokenType::STRING)
      expect(tokens[0].value).to eq("hello\nworld")
      expect(tokens[1].type).to eq(Ruby::Rego::TokenType::STRING)
      expect(tokens[1].value).to eq("quote: \"")
    end

    it "tokenizes raw strings" do
      tokens = tokenize("`raw \\{value}`")

      expect(tokens[0].type).to eq(Ruby::Rego::TokenType::RAW_STRING)
      expect(tokens[0].value).to eq("raw {value}")
    end

    it "tokenizes operators" do
      source = ":= == != <= >= < > + - * / % | & ="
      types = tokenize(source).map(&:type)

      expect(types).to eq(
        [
          Ruby::Rego::TokenType::ASSIGN,
          Ruby::Rego::TokenType::EQ,
          Ruby::Rego::TokenType::NEQ,
          Ruby::Rego::TokenType::LTE,
          Ruby::Rego::TokenType::GTE,
          Ruby::Rego::TokenType::LT,
          Ruby::Rego::TokenType::GT,
          Ruby::Rego::TokenType::PLUS,
          Ruby::Rego::TokenType::MINUS,
          Ruby::Rego::TokenType::STAR,
          Ruby::Rego::TokenType::SLASH,
          Ruby::Rego::TokenType::PERCENT,
          Ruby::Rego::TokenType::PIPE,
          Ruby::Rego::TokenType::AMPERSAND,
          Ruby::Rego::TokenType::UNIFY,
          Ruby::Rego::TokenType::EOF
        ]
      )
    end

    it "tokenizes delimiters" do
      source = "()[]{}.,;:_"
      types = tokenize(source).map(&:type)

      expect(types).to eq(
        [
          Ruby::Rego::TokenType::LPAREN,
          Ruby::Rego::TokenType::RPAREN,
          Ruby::Rego::TokenType::LBRACKET,
          Ruby::Rego::TokenType::RBRACKET,
          Ruby::Rego::TokenType::LBRACE,
          Ruby::Rego::TokenType::RBRACE,
          Ruby::Rego::TokenType::DOT,
          Ruby::Rego::TokenType::COMMA,
          Ruby::Rego::TokenType::SEMICOLON,
          Ruby::Rego::TokenType::COLON,
          Ruby::Rego::TokenType::UNDERSCORE,
          Ruby::Rego::TokenType::EOF
        ]
      )
    end

    it "tokenizes complex sequences" do
      source = <<~REGO
        package auth
        import data.users as users

        allow := input.user == "admin"
      REGO

      types = tokenize(source).map(&:type)

      expect(types).to include(
        Ruby::Rego::TokenType::PACKAGE,
        Ruby::Rego::TokenType::IMPORT,
        Ruby::Rego::TokenType::ASSIGN,
        Ruby::Rego::TokenType::EQ,
        Ruby::Rego::TokenType::STRING,
        Ruby::Rego::TokenType::EOF
      )
    end

    it "skips comments and whitespace" do
      source = "allow # comment\n true"
      tokens = tokenize(source)

      expect(tokens[0].type).to eq(Ruby::Rego::TokenType::IDENT)
      expect(tokens[0].value).to eq("allow")
      expect(tokens[1].type).to eq(Ruby::Rego::TokenType::TRUE)
      expect(tokens[2].type).to eq(Ruby::Rego::TokenType::EOF)
    end

    it "tracks token locations" do
      tokens = tokenize("a\n  b")

      first = tokens[0].location
      second = tokens[1].location

      expect(first.line).to eq(1)
      expect(first.column).to eq(1)
      expect(first.offset).to eq(0)
      expect(first.length).to eq(1)

      expect(second.line).to eq(2)
      expect(second.column).to eq(3)
      expect(second.offset).to eq(4)
      expect(second.length).to eq(1)
    end

    it "handles empty input" do
      tokens = tokenize("")

      expect(tokens.map(&:type)).to eq([Ruby::Rego::TokenType::EOF])
    end

    it "handles whitespace-only input" do
      tokens = tokenize(" \t\n  ")

      expect(tokens.map(&:type)).to eq([Ruby::Rego::TokenType::EOF])
    end

    it "handles comment-only input" do
      tokens = tokenize("# comment only")

      expect(tokens.map(&:type)).to eq([Ruby::Rego::TokenType::EOF])
    end
  end

  describe "error handling" do
    it "raises on unexpected characters" do
      expect { tokenize("@") }.to raise_error(Ruby::Rego::LexerError, /Unexpected character/)
    end

    it "raises on unterminated strings" do
      expect { tokenize("\"unterminated") }.to raise_error(Ruby::Rego::LexerError, /Unterminated string literal/)
    end

    it "raises on unterminated raw strings" do
      expect { tokenize("`unterminated") }.to raise_error(Ruby::Rego::LexerError, /Unterminated raw string literal/)
    end

    it "raises on invalid number exponents" do
      expect { tokenize("1e+") }.to raise_error(Ruby::Rego::LexerError, /Invalid number exponent/)
    end

    it "raises on leading zero numbers" do
      expect { tokenize("01") }.to raise_error(Ruby::Rego::LexerError, /Invalid number literal/)
    end

    it "raises on trailing decimal dots" do
      expect { tokenize("1.") }.to raise_error(Ruby::Rego::LexerError, /Invalid number literal/)
    end

    it "raises on leading decimal dots" do
      expect { tokenize(".5") }.to raise_error(Ruby::Rego::LexerError, /Invalid number literal/)
    end

    it "raises on invalid escape sequences" do
      expect { tokenize("\"bad\\q\"") }.to raise_error(Ruby::Rego::LexerError, /Invalid escape sequence/)
    end
  end
end

# rubocop:enable Metrics/BlockLength
