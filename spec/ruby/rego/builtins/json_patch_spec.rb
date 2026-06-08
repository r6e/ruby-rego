# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
# All expected values were verified against `opa eval` 1.17.

RSpec.describe "json.patch" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  def patch(document, operations)
    registry.call("json.patch", [document, operations]).to_ruby
  end

  it "applies add, remove, and replace" do
    expect(patch({ "a" => 1 }, [{ "op" => "add", "path" => "/b", "value" => 2 }])).to eq("a" => 1, "b" => 2)
    expect(patch({ "a" => 1, "b" => 2 }, [{ "op" => "remove", "path" => "/a" }])).to eq("b" => 2)
    expect(patch({ "a" => { "x" => 1 } }, [{ "op" => "replace", "path" => "/a/x", "value" => 9 }]))
      .to eq("a" => { "x" => 9 })
  end

  it "handles arrays: index insert, append (-), and bounds" do
    expect(patch([1, 2, 3], [{ "op" => "add", "path" => "/1", "value" => 9 }])).to eq([1, 9, 2, 3])
    expect(patch([1, 2, 3], [{ "op" => "add", "path" => "/-", "value" => 4 }])).to eq([1, 2, 3, 4])
    expect(patch([10, 20], [{ "op" => "replace", "path" => "/0", "value" => 99 }])).to eq([99, 20])
    expect(registry.call("json.patch", [[1, 2], [{ "op" => "add", "path" => "/5", "value" => 9 }]]))
      .to be_a(Ruby::Rego::UndefinedValue)
  end

  it "applies move, copy, and test" do
    expect(patch({ "a" => 1 }, [{ "op" => "move", "from" => "/a", "path" => "/b" }])).to eq("b" => 1)
    expect(patch({ "a" => 1 }, [{ "op" => "copy", "from" => "/a", "path" => "/b" }])).to eq("a" => 1, "b" => 1)
    expect(patch({ "a" => 1 }, [{ "op" => "test", "path" => "/a", "value" => 1 }])).to eq("a" => 1)
    expect(patch({ "a" => 1 }, [{ "op" => "test", "path" => "/a", "value" => 1.0 }])).to eq("a" => 1) # numeric eq
  end

  it "unescapes ~1 (/) and ~0 (~) in pointers and treats empty path as the whole document" do
    expect(patch({ "a/b" => 1 }, [{ "op" => "replace", "path" => "/a~1b", "value" => 9 }])).to eq("a/b" => 9)
    expect(patch({ "a~x" => 1 }, [{ "op" => "replace", "path" => "/a~0x", "value" => 9 }])).to eq("a~x" => 9)
    expect(patch({}, [{ "op" => "add", "path" => "", "value" => { "z" => 1 } }])).to eq("z" => 1)
    expect(patch(5, [{ "op" => "replace", "path" => "", "value" => 9 }])).to eq(9)
  end

  it "treats an all-slash path as the empty-string key, not the whole document (RFC 6901)" do
    # "" is the whole document; "/" (and "//") is the "" key — OPA distinguishes them.
    expect(patch({ "a" => 1 }, [{ "op" => "add", "path" => "/", "value" => 99 }])).to eq("a" => 1, "" => 99)
    expect(patch({ "" => 5 }, [{ "op" => "remove", "path" => "/" }])).to eq({})
    expect(patch({ "a" => 1 }, [{ "op" => "add", "path" => "//a", "value" => 9 }])).to eq("a" => 9)
    expect(patch({ "a" => 1 }, [{ "op" => "add", "path" => "//", "value" => 99 }])).to eq("a" => 1, "" => 99)
    expect(patch({ "a" => 1 }, [{ "op" => "add", "path" => "///", "value" => 99 }])).to eq("a" => 1, "" => 99)
  end

  it "applies operations in order" do
    ops = [{ "op" => "add", "path" => "/b", "value" => 2 }, { "op" => "remove", "path" => "/a" }]
    expect(patch({ "a" => 1 }, ops)).to eq("b" => 2)
  end

  it "accepts an array-form path with string or integer index segments" do
    expect(patch({ "a" => 1 }, [{ "op" => "add", "path" => ["b"], "value" => 2 }])).to eq("a" => 1, "b" => 2)
    expect(patch({ "a" => [1, 2] }, [{ "op" => "add", "path" => ["a", 1], "value" => 9 }])).to eq("a" => [1, 9, 2])
  end

  it "is undefined for a failed test, a missing target, a bad op, or a non-array operand" do
    [
      [{ "a" => 1 }, [{ "op" => "test", "path" => "/a", "value" => 2 }]],
      [{ "a" => 1 }, [{ "op" => "remove", "path" => "/x" }]],
      [{ "a" => 1 }, [{ "op" => "replace", "path" => "/x", "value" => 9 }]],
      [{ "a" => 1 }, [{ "op" => "add", "path" => "/b/c", "value" => 9 }]],
      [{ "a" => 1 }, [{ "op" => "bogus", "path" => "/a" }]],
      [{ "a" => 1 }, [{ "op" => "add", "path" => "/b" }]], # add without value
      [{ "a" => 1 }, [{ "path" => "/a", "value" => 2 }]],  # missing op
      [{ "a" => 1 }, "notarray"],
      [{ "a" => 1 }, [42]] # operation not an object
    ].each do |document, operations|
      expect(registry.call("json.patch", [document, operations])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end
# rubocop:enable Metrics/BlockLength
