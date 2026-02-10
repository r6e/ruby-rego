# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe "string builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  it "concatenates arrays of strings" do
    expect(registry.call("concat", [",", %w[a b]]).to_ruby).to eq("a,b")
    expect(registry.call("concat", ["-", []]).to_ruby).to eq("")
  end

  it "raises for invalid concat arguments" do
    first = registry.call("concat", [1, ["a"]])
    second = registry.call("concat", [",", "a"])
    third = registry.call("concat", [",", [1]])

    expect(first).to be_a(Ruby::Rego::UndefinedValue)
    expect(second).to be_a(Ruby::Rego::UndefinedValue)
    expect(third).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "checks substring containment" do
    expect(registry.call("contains", %w[hello ell]).to_ruby).to be(true)
    expect(registry.call("contains", ["hello", ""]).to_ruby).to be(true)
    expect(registry.call("contains", %w[café fé]).to_ruby).to be(true)
  end

  it "raises for invalid contains arguments" do
    result = registry.call("contains", [1, "a"])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "checks prefixes and suffixes" do
    expect(registry.call("startswith", %w[hello he]).to_ruby).to be(true)
    expect(registry.call("startswith", ["hello", ""]).to_ruby).to be(true)
    expect(registry.call("endswith", %w[hello lo]).to_ruby).to be(true)
    expect(registry.call("endswith", ["hello", ""]).to_ruby).to be(true)
    expect(registry.call("startswith", %w[πρόβα πρ]).to_ruby).to be(true)
  end

  it "raises for invalid prefix and suffix arguments" do
    first = registry.call("startswith", ["hello", 1])
    second = registry.call("endswith", [1, "lo"])

    expect(first).to be_a(Ruby::Rego::UndefinedValue)
    expect(second).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "formats integers in a base" do
    expect(registry.call("format_int", [10, 2]).to_ruby).to eq("1010")
    expect(registry.call("format_int", [255, 16]).to_ruby).to eq("ff")
    expect(registry.call("format_int", [-10, 10]).to_ruby).to eq("-10")
  end

  it "raises for invalid format_int arguments" do
    first = registry.call("format_int", [10.5, 10])
    second = registry.call("format_int", [10, 1])
    third = registry.call("format_int", [10, 37])
    fourth = registry.call("format_int", [10, "2"])

    expect(first).to be_a(Ruby::Rego::UndefinedValue)
    expect(second).to be_a(Ruby::Rego::UndefinedValue)
    expect(third).to be_a(Ruby::Rego::UndefinedValue)
    expect(fourth).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "finds the index of a substring" do
    expect(registry.call("indexof", %w[hello ll]).to_ruby).to eq(2)
    expect(registry.call("indexof", %w[hello z]).to_ruby).to eq(-1)
    expect(registry.call("indexof", %w[café é]).to_ruby).to eq(3)
  end

  it "raises for invalid indexof arguments" do
    result = registry.call("indexof", ["hello", 2])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "lowercases and uppercases strings" do
    expect(registry.call("lower", ["HeLLo"]).to_ruby).to eq("hello")
    expect(registry.call("upper", ["hello"]).to_ruby).to eq("HELLO")
    expect(registry.call("lower", ["CAF\u00c9"]).to_ruby).to eq("caf\u00e9")
    expect(registry.call("upper", ["caf\u00e9"]).to_ruby).to eq("CAF\u00c9")
  end

  it "raises for invalid case arguments" do
    result = registry.call("lower", [1])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "splits strings by delimiter" do
    expect(registry.call("split", ["a,b,c", ","]).to_ruby).to eq(%w[a b c])
    expect(registry.call("split", ["a,", ","]).to_ruby).to eq(["a", ""])
  end

  it "raises for invalid split arguments" do
    result = registry.call("split", ["a", 1])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "formats strings with sprintf" do
    expect(registry.call("sprintf", ["Hello %s %d", ["world", 2]]).to_ruby)
      .to eq("Hello world 2")
  end

  it "raises for invalid sprintf arguments" do
    first = registry.call("sprintf", ["%d", []])
    second = registry.call("sprintf", ["%d", ["x"]])
    third = registry.call("sprintf", ["%s", "not array"])

    expect(first).to be_a(Ruby::Rego::UndefinedValue)
    expect(second).to be_a(Ruby::Rego::UndefinedValue)
    expect(third).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "extracts substrings" do
    expect(registry.call("substring", ["hello", 1, 3]).to_ruby).to eq("ell")
    expect(registry.call("substring", ["hello", 2, 10]).to_ruby).to eq("llo")
    expect(registry.call("substring", ["hello", 10, 2]).to_ruby).to eq("")
    expect(registry.call("substring", ["caf\u00e9", 1, 2]).to_ruby).to eq("af")
  end

  it "raises for invalid substring arguments" do
    first = registry.call("substring", ["hello", -1, 2])
    second = registry.call("substring", ["hello", 1, -2])
    third = registry.call("substring", ["hello", "1", 2])

    expect(first).to be_a(Ruby::Rego::UndefinedValue)
    expect(second).to be_a(Ruby::Rego::UndefinedValue)
    expect(third).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "trims characters from both ends" do
    expect(registry.call("trim", ["..hello..", "."]).to_ruby).to eq("hello")
    expect(registry.call("trim", ["--hello..", "-."]).to_ruby).to eq("hello")
    expect(registry.call("trim", ["hello", ""]).to_ruby).to eq("hello")
  end

  it "trims characters from the left or right" do
    expect(registry.call("trim_left", %w[xxhello x]).to_ruby).to eq("hello")
    expect(registry.call("trim_right", %w[helloxx x]).to_ruby).to eq("hello")
    expect(registry.call("trim_left", ["hello", ""]).to_ruby).to eq("hello")
    expect(registry.call("trim_right", ["hello", ""]).to_ruby).to eq("hello")
  end

  it "raises for invalid trim arguments" do
    result = registry.call("trim", ["hello", 1])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "trims whitespace" do
    expect(registry.call("trim_space", ["  hello\t"]).to_ruby).to eq("hello")
  end

  it "raises for invalid trim_space arguments" do
    result = registry.call("trim_space", [1])

    expect(result).to be_a(Ruby::Rego::UndefinedValue)
  end

  it "allows repeated registration" do
    expect { Ruby::Rego::Builtins::Strings.register! }.not_to raise_error
    expect { Ruby::Rego::Builtins::Strings.register! }.not_to raise_error
  end
end

# rubocop:enable Metrics/BlockLength
