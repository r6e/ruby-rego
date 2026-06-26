# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Builtins::Codecs::JsonDecoder do
  def parse(string)
    described_class.parse(string)
  end

  # A JSON \uXXXX escape for a code point (built so the escape survives the test source verbatim — a
  # typed surrogate-pair escape would itself collapse to the combined character).
  def u(code)
    format('\u%<code>04x', code: code)
  end

  describe "number text preservation (OPA json.Number fidelity)" do
    it "keeps a fractional number's verbatim text as a Number" do
      %w[1.50 0.30 100.00 3.14159265358979].each do |text|
        value = parse(text)
        expect(value).to be_a(Ruby::Rego::Number)
        expect(value.to_s).to eq(text)
      end
    end

    it "keeps an exponent number's verbatim text as a Number (no Float collapse to Infinity)" do
      %w[1e999 1e2 1E2 -1e-300].each do |text|
        value = parse(text)
        expect(value).to be_a(Ruby::Rego::Number)
        expect(value.to_s).to eq(text)
      end
    end

    it "parses a plain integer as an exact Integer (arbitrary precision)" do
      expect(parse("42")).to eq(42)
      expect(parse("9007199254740993")).to eql(9_007_199_254_740_993)
      expect(parse("123456789012345678901234567890")).to eql(123_456_789_012_345_678_901_234_567_890)
    end

    it "preserves -0 as a Number (OPA keeps the sign) that still equals 0" do
      value = parse("-0")
      expect(value).to be_a(Ruby::Rego::Number)
      expect(value.to_s).to eq("-0")
      expect(value).to eq(0)
    end
  end

  describe "strict structure (RFC 8259 / Go encoding/json)" do
    it "rejects comments, trailing commas, leading zeros, bare fractions and trailing content" do
      ['{"a":1} // c', '{"a":1} /* c */', "[1,2,]", '{"a":1,}', "01", "1.", ".5", "+1",
       "NaN", "Infinity", '{"a":1}x', "[1] [2]", "", "  "].each do |bad|
        expect { parse(bad) }.to raise_error(described_class::ParseError), "expected #{bad.inspect} to be rejected"
      end
    end

    it "takes the last value for a duplicate object key (matching Go)" do
      expect(parse('{"a":1,"a":2}')).to eq("a" => 2)
    end

    it "accepts surrounding and interior insignificant whitespace" do
      expect(parse(%(  { "a" : [ 1 , 2 ] }  ))).to eq("a" => [1, 2])
    end
  end

  describe "magnitude cap (same bound as the lexer; protects against a rational-materialisation DoS)" do
    it "accepts a number at the realistic edge" do
      expect(parse("1e30102")).to be_a(Ruby::Rego::Number)
    end

    it "rejects a number beyond the cap rather than materialising it" do
      ["1e30103", "1e99999", "1#{"0" * 40_000}"].each do |over|
        expect { parse(over) }.to raise_error(described_class::ParseError)
      end
    end

    # An exponent of ~19+ digits saturates BigDecimal at construction (it does not raise): positive to
    # Infinity, negative underflowing to 0. Both must be rejected up front (else the positive one raises
    # FloatDomainError on later use, and the negative one is silently mis-evaluated as 0).
    it "rejects a saturating-exponent number up front, both directions" do
      expect { parse("1e9999999999999999999") }.to raise_error(described_class::ParseError)
      expect { parse("1e-9999999999999999999") }.to raise_error(described_class::ParseError)
    end

    it "still accepts a genuine zero carrying a huge exponent" do
      expect(parse("0e-9999999999999999999")).to be_a(Ruby::Rego::Number)
      expect(parse("0e-9999999999999999999")).to eq(0)
    end
  end

  describe "nesting cap (load-bearing: bounds the downstream recursive Value.from_ruby)" do
    it "accepts nesting at the cap" do
      expect(parse("#{"[" * described_class::MAX_DEPTH}1#{"]" * described_class::MAX_DEPTH}")).not_to be_nil
    end

    it "rejects nesting past the cap without a SystemStackError" do
      ["[" * 200, "[" * 500_000, '{"a":' * 500_000].each do |deep|
        expect { parse(deep) }.to raise_error(described_class::ParseError)
      end
    end
  end

  describe "string and encoding handling" do
    it "decodes escapes and surrogate pairs" do
      expect(parse('"a\nb\t\"é😀"')).to eq("a\nb\t\"é😀")
    end

    it "combines a high+low \\u surrogate pair into one character (matching Go)" do
      expect(parse(%("#{u(0xD83D)}#{u(0xDE00)}"))).to eq("😀")
    end

    it "rejects an invalid escape" do
      expect { parse('"\q"') }.to raise_error(described_class::ParseError)
    end

    it "maps unpaired surrogates to U+FFFD, keeping a trailing non-surrogate (matching Go)" do
      expect(parse('"\ud800x"')).to eq("\u{FFFD}x")             # lone high
      expect(parse('"\udc00"')).to eq("\u{FFFD}")               # lone low
      expect(parse('"\ud800\ud800"')).to eq("\u{FFFD}\u{FFFD}") # high + high
      expect(parse('"\ud800A"')).to eq("\u{FFFD}A")             # high then a literal char (no \u follows)
    end

    # A high surrogate followed by another high surrogate must NOT consume the second: the second pairs
    # with the third escape, so the result is U+FFFD then the combined character (Go re-processes it).
    it "re-processes a high surrogate that follows an unpaired high surrogate (matching Go)" do
      input = %("#{u(0xD800)}#{u(0xD83D)}#{u(0xDE00)}")
      expect(parse(input)).to eq("\u{FFFD}😀")
    end

    it "re-tags a binary input whose content is valid UTF-8 back to UTF-8" do
      value = parse(%({"k":"é"}).b)
      expect(value["k"].encoding).to eq(Encoding::UTF_8)
      expect(value["k"]).to eq("é")
    end

    it "keeps genuinely invalid bytes as raw ASCII-8BIT" do
      value = parse(%({"k":"\xFF"}).b)
      expect(value["k"].bytes).to eq([0xFF])
    end

    # Regression: byte_safe_encoding? admits an ascii-compatible single-byte non-UTF-8 encoding
    # (ISO-8859-1 / Windows-1252). A string body with a literal high byte AND a multibyte \uXXXX escape
    # used to append a UTF-8 char onto a Latin-1 accumulator -> uncaught Encoding::CompatibilityError,
    # breaking totality (and a host-API-reachable DoS via json.is_valid, which does not flow through
    # Codecs.decoded). parse now normalizes non-UTF-8 input to bytes up front, so it returns raw bytes.
    it "does not raise Encoding::CompatibilityError on a Latin-1 high byte plus a \\uXXXX escape" do
      latin1 = "\"\xE9\\u00e9\"".dup.force_encoding(Encoding::ISO_8859_1)
      windows = "\"\\u00e9\xE9\"".dup.force_encoding("Windows-1252")
      expect { parse(latin1) }.not_to raise_error
      expect { parse(windows) }.not_to raise_error
      expect(parse(latin1).encoding).to eq(Encoding::BINARY)
    end

    it "rejects a control character inside a string" do
      expect { parse(%({"k":"a\tb"})) }.to raise_error(described_class::ParseError)
    end
  end

  describe "totality (only ever raises ParseError; never an uncaught error or SystemStackError)" do
    # A non-ParseError escaping any of these would fail the example: the registry only rescues
    # BuiltinArgumentError, so anything else would abort a whole policy evaluation.
    def parses_totally?(string)
      parse(string)
      true
    rescue described_class::ParseError
      true
    end

    it "maps every truncation of a rich document to ParseError or a value" do
      seed = '{"a":[1,2.5,{"b":"x😀"}],"c":1e9,"d":true,"e":-0}'
      offsets = (0..seed.bytesize)
      expect(offsets.all? { |offset| parses_totally?(seed.byteslice(0, offset)) }).to be(true)
    end

    it "handles arbitrary binary, deep nesting and huge numbers without an uncaught error" do
      inputs = [(0..255).map(&:chr).join.b, "\xFF\xFE\xC0".b, "\x00\x00".b,
                "[" * 500_000, "1#{"0" * 1_000_000}", %({"k":"a#{'\\u0000' * 1000}"})]
      expect(inputs.all? { |bytes| parses_totally?(bytes) }).to be(true)
    end
  end

  describe ".valid?" do
    it "is true for well-formed strict JSON and false otherwise" do
      expect(described_class.valid?('{"a":[1,2.5]}')).to be(true)
      expect(described_class.valid?('{"a":1} // c')).to be(false)
      expect(described_class.valid?("{bad}")).to be(false)
    end
  end
end
# rubocop:enable Metrics/BlockLength
