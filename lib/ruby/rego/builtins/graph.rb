# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

module Ruby
  module Rego
    module Builtins
      # Graph-walk built-ins (graph.reachable, graph.reachable_paths), matching OPA. A graph is
      # an object mapping each node to its neighbours (an array or set); the initial set is an
      # array or set of nodes. A neighbour that is not itself a key in the graph is followed but
      # not treated as a node (it has no edges), exactly as OPA's implementation does.
      #
      # Node identity uses Ruby Hash/Set membership. Like the rest of the gem (and unlike OPA),
      # numbers 1 and 1.0 are distinct here, so a graph whose node labels mix integer and float
      # forms of the same value can diverge from OPA — part of the known SetValue/ObjectValue
      # numeric-normalisation gap. String-labelled graphs (the common case) are exact.
      module Graph
        extend RegistryHelpers

        GRAPH_FUNCTIONS = {
          "graph.reachable" => { arity: 2, handler: :reachable },
          "graph.reachable_paths" => { arity: 2, handler: :reachable_paths }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, GRAPH_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # The set of nodes reachable from the initial set. A node is included only when it is a
        # key in the graph (a dangling neighbour is skipped); cycles terminate.
        #
        # @param graph_value [Ruby::Rego::Value]
        # @param initial_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::SetValue]
        def self.reachable(graph_value, initial_value)
          graph = object_arg(graph_value, "graph.reachable")
          queue = vertices(initial_value, "graph.reachable")
          SetValue.new(walk_reachable(graph, queue, Set.new(queue)))
        end

        # Worklist over `queue`; `seen` dedups at enqueue (not after pop) so each node is queued
        # at most once, and dangling neighbours (not graph nodes) are never enqueued — bounding
        # the work to O(V+E) without changing which nodes are reached. The result is an unordered
        # set, so pop (O(1)) over shift (O(n)).
        # @return [Set]
        def self.walk_reachable(graph, queue, seen)
          reached = Set.new
          until queue.empty?
            node = queue.pop
            next unless graph.key?(node)

            reached.add(node)
            neighbours(graph[node]).each { |adj| queue.push(adj) if seen.add?(adj) && graph.key?(adj) }
          end
          reached
        end
        private_class_method :walk_reachable

        # The set of all paths (arrays) walkable from the initial set, stopping at leaves and
        # at the first repeated node on a path (cycle).
        #
        # @param graph_value [Ruby::Rego::Value]
        # @param initial_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::SetValue]
        def self.reachable_paths(graph_value, initial_value)
          graph = object_arg(graph_value, "graph.reachable_paths")
          paths = Set.new # @type var paths: Set[Array[untyped]]
          vertices(initial_value, "graph.reachable_paths").each do |node|
            next unless graph.key?(node)

            walk_roots(graph, node, paths)
          end
          SetValue.new(paths)
        end

        # @return [void]
        def self.walk_roots(graph, node, paths)
          edges = neighbours(graph[node])
          return paths.add([node]) if edges.empty?

          edges.each { |neighbour| build_paths(graph, neighbour, [node], paths, Set[node]) }
        end
        private_class_method :walk_roots

        # Recursively extends `path` from `root`, committing a finished path when `root` is not a
        # graph node, is a leaf, or closes a cycle (any neighbour already on the path). Mirrors
        # OPA's pathBuilder (the result is a set, so one commit per node suffices).
        # @return [void]
        def self.build_paths(graph, root, path, paths, reached)
          return paths.add(path) unless graph.key?(root)

          extended = path + [root]
          edges = neighbours(graph[root])
          seen = reached + [root]
          fresh = edges.reject { |neighbour| seen.include?(neighbour) }
          paths.add(extended) if edges.empty? || fresh.length < edges.length
          fresh.each { |neighbour| build_paths(graph, neighbour, extended, paths, seen) }
        end
        private_class_method :build_paths

        # @return [Hash]
        def self.object_arg(value, context)
          Base.assert_type(value, expected: ObjectValue, context: context)
          value.to_ruby
        end
        private_class_method :object_arg

        # The initial set as an array of node values; a non-array/set argument is undefined.
        # @return [Array]
        def self.vertices(value, context)
          Base.assert_type(value, expected: [ArrayValue, SetValue], context: context)
          value.to_ruby.to_a
        end
        private_class_method :vertices

        # A node's neighbours: the array/set value's members, or none for any other value.
        # @return [Array]
        def self.neighbours(edges)
          case edges
          when ::Array then edges
          when ::Set then edges.to_a
          else []
          end
        end
        private_class_method :neighbours
      end
    end
  end
end

Ruby::Rego::Builtins::Graph.register!
