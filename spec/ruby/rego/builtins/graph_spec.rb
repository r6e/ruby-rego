# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
# All expected values below were verified against `opa eval` 1.17.
RSpec.describe "graph builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  describe "graph.reachable" do
    let(:graph) { { "a" => ["b"], "b" => ["c"], "c" => [] } }

    it "returns the set of reachable nodes" do
      expect(registry.call("graph.reachable", [graph, ["a"]]).to_ruby).to eq(Set["a", "b", "c"])
      expect(registry.call("graph.reachable", [graph, Set["b"]]).to_ruby).to eq(Set["b", "c"])
    end

    it "terminates on cycles and accepts set-valued edges" do
      expect(registry.call("graph.reachable", [{ "a" => ["b"], "b" => ["a"] }, ["a"]]).to_ruby)
        .to eq(Set["a", "b"])
      expect(registry.call("graph.reachable", [{ "a" => Set["b", "c"], "b" => [], "c" => [] }, ["a"]]).to_ruby)
        .to eq(Set["a", "b", "c"])
    end

    it "excludes a neighbour that is not itself a node (key) in the graph (matching OPA)" do
      expect(registry.call("graph.reachable", [{ "a" => ["b"] }, ["a"]]).to_ruby).to eq(Set["a"])
      expect(registry.call("graph.reachable", [{}, []]).to_ruby).to eq(Set.new)
    end

    it "is undefined for a non-object graph or non-array/set initial set" do
      expect(registry.call("graph.reachable", [["a"], ["a"]])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("graph.reachable", [{ "a" => [] }, "a"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "graph.reachable_paths" do
    it "returns every path, splitting at branches" do
      graph = { "a" => %w[b c], "b" => ["d"], "c" => ["d"], "d" => [] }
      expect(registry.call("graph.reachable_paths", [graph, ["a"]]).to_ruby)
        .to eq(Set[%w[a b d], %w[a c d]])
    end

    it "stops a path at the first repeated node (cycle)" do
      expect(registry.call("graph.reachable_paths", [{ "a" => ["b"], "b" => ["a"] }, ["a"]]).to_ruby)
        .to eq(Set[%w[a b]])
      expect(registry.call("graph.reachable_paths", [{ "a" => ["b"], "b" => ["c"], "c" => ["a"] }, ["a"]]).to_ruby)
        .to eq(Set[%w[a b c]])
    end

    it "yields a single-node path for a node with no edges" do
      expect(registry.call("graph.reachable_paths", [{ "a" => [] }, ["a"]]).to_ruby).to eq(Set[["a"]])
    end

    it "is undefined for a non-object graph or non-array/set initial set" do
      expect(registry.call("graph.reachable_paths", [42, ["a"]])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end
# rubocop:enable Metrics/BlockLength
