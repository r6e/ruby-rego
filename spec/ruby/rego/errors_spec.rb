# frozen_string_literal: true

RSpec.describe Ruby::Rego::Location do
  describe "#to_s" do
    it "renders all parts when present" do
      location = described_class.new(line: 3, column: 12, offset: 42, length: 5)

      expect(location.to_s).to eq("line 3, column 12, offset 42, length 5")
    end

    it "omits optional parts when nil" do
      location = described_class.new(line: 1, column: 2)

      expect(location.to_s).to eq("line 1, column 2")
    end
  end
end

RSpec.describe Ruby::Rego::LexerError do
  it "includes line and column in the message" do
    error = described_class.new("Unexpected character", line: 2, column: 8)

    expect(error.message).to include("Unexpected character")
    expect(error.message).to include("line 2, column 8")
    expect(error.line).to eq(2)
    expect(error.column).to eq(8)
  end
end

RSpec.describe Ruby::Rego::ParserError do
  it "includes context in the message" do
    error = described_class.from_position(
      "Unexpected token",
      position: { line: 4, column: 1 },
      context: "rule body"
    )

    expect(error.message).to include("Unexpected token")
    expect(error.message).to include("context: rule body")
    expect(error.line).to eq(4)
    expect(error.column).to eq(1)
    expect(error.context).to eq("rule body")
  end
end

RSpec.describe Ruby::Rego::EvaluationError do
  it "includes rule context in the message" do
    error = described_class.new("Rule failed", rule: "data.allow")

    expect(error.message).to include("Rule failed")
    expect(error.message).to include("rule: data.allow")
    expect(error.rule).to eq("data.allow")
  end
end

RSpec.describe Ruby::Rego::TypeError do
  it "includes expected and actual in the message" do
    error = described_class.new(
      "Type mismatch",
      expected: "string",
      actual: "number",
      context: "input.user"
    )

    expect(error.message).to include("Type mismatch")
    expect(error.message).to include("expected: string")
    expect(error.message).to include("actual: number")
    expect(error.message).to include("context: input.user")
    expect(error.expected).to eq("string")
    expect(error.actual).to eq("number")
    expect(error.context).to eq("input.user")
  end
end

RSpec.describe Ruby::Rego::BuiltinArgumentError do
  it "includes expected and actual in the message" do
    error = described_class.new(
      "Invalid builtin argument",
      expected: "string",
      actual: "number",
      context: "count"
    )

    expect(error.message).to include("Invalid builtin argument")
    expect(error.message).to include("expected: string")
    expect(error.message).to include("actual: number")
    expect(error.message).to include("context: count")
    expect(error.expected).to eq("string")
    expect(error.actual).to eq("number")
    expect(error.context).to eq("count")
  end
end

RSpec.describe Ruby::Rego::UnificationError do
  it "includes pattern and value in the message" do
    error = described_class.new("Unification failed", pattern: "x", value: 42)

    expect(error.message).to include("Unification failed")
    expect(error.message).to include("pattern: x")
    expect(error.message).to include("value: 42")
    expect(error.pattern).to eq("x")
    expect(error.value).to eq(42)
  end
end
