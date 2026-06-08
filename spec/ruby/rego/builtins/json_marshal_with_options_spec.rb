# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
# All expected values were verified against `opa eval` 1.17.

RSpec.describe "json.marshal_with_options" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  def marshal(value, options)
    registry.call("json.marshal_with_options", [value, options]).to_ruby
  end

  it "is compact (sorted keys) with no options or pretty: false" do
    expect(marshal({ "b" => 2, "a" => 1 }, {})).to eq('{"a":1,"b":2}')
    expect(marshal({ "a" => 1 }, { "pretty" => false })).to eq('{"a":1}')
  end

  it "pretty-prints with the given indent when pretty: true" do
    expect(marshal({ "b" => 2, "a" => 1 }, { "indent" => "  ", "pretty" => true }))
      .to eq("{\n  \"a\": 1,\n  \"b\": 2\n}")
  end

  it "defaults the indent to a tab when pretty: true and no indent is given" do
    expect(marshal({ "a" => 1 }, { "pretty" => true })).to eq("{\n\t\"a\": 1\n}")
  end

  it "implies pretty when an indent or prefix is given without an explicit pretty" do
    expect(marshal({ "a" => 1 }, { "indent" => "    " })).to eq("{\n    \"a\": 1\n}")
    expect(marshal([1], { "prefix" => ">>" })).to eq(">>[\n>>\t1\n>>]")
  end

  it "prepends the prefix to every line (Go MarshalIndent), incl. the first" do
    expect(marshal([1, 2], { "pretty" => true, "prefix" => ">>", "indent" => "\t" }))
      .to eq(">>[\n>>\t1,\n>>\t2\n>>]")
  end

  it "HTML-escapes string values but not the structural indent/prefix" do
    expect(marshal({ "a" => "<b>&" }, { "pretty" => true })).to eq("{\n\t\"a\": \"\\u003cb\\u003e\\u0026\"\n}")
    # an indent containing '>' must stay literal, not become >
    expect(marshal([1], { "indent" => "->" })).to eq("[\n->1\n]")
  end

  it "inserts a backslash-bearing indent or prefix literally (no gsub back-reference interpretation)" do
    expect(marshal([1], { "indent" => '\&' })).to eq("[\n\\&1\n]")
    expect(marshal([1], { "indent" => '\1' })).to eq("[\n\\11\n]")
    expect(marshal([1], { "indent" => "\\" })).to eq("[\n\\1\n]")
    expect(marshal([1], { "prefix" => '\&', "indent" => "  " })).to eq("\\&[\n\\&  1\n\\&]")
  end

  it "does not prefix a newline that is inside the indent string itself (matching Go)" do
    expect(marshal([1], { "indent" => "a\nb", "prefix" => ">" })).to eq(">[\n>a\nb1\n>]")
  end

  it "keeps a NUL byte in the prefix or indent literal (no collision with the indent sentinel)" do
    expect(marshal([1], { "prefix" => "\x00", "indent" => "  " }).bytes)
      .to eq([0, 91, 10, 0, 32, 32, 49, 10, 0, 93])
    expect(marshal([1], { "indent" => "\x00" }).bytes).to eq([91, 10, 0, 49, 10, 93])
  end

  it "is undefined for a non-object options arg, unknown key, or wrongly-typed option value" do
    [
      [{ "a" => 1 }, "notobj"],
      [{ "a" => 1 }, { "bogus" => 1 }],
      [{ "a" => 1 }, { "pretty" => "yes" }],
      [{ "a" => 1 }, { "indent" => 1 }],
      [{ "a" => 1 }, { "prefix" => true }]
    ].each do |value, options|
      expect(registry.call("json.marshal_with_options", [value, options])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end
# rubocop:enable Metrics/BlockLength
