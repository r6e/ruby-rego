# frozen_string_literal: true

module Ruby
  module Rego
    # Bundles compiled rule metadata for fast evaluation.
    class CompiledModule
      # Create a compiled module bundle.
      #
      # @param package_path [Array<String>] module package path
      # @param rules_by_name [Hash{String => Array<AST::Rule>}] indexed rules
      # @param imports [Array<AST::Import>] imports from the module
      # @param dependency_graph [Hash{String => Array<String>}] rule dependencies
      def initialize(package_path:, rules_by_name:, imports: [], dependency_graph: {})
        state = {
          package_path: package_path,
          rules_by_name: rules_by_name,
          imports: imports,
          dependency_graph: dependency_graph
        }
        @package_path,
          @rules_by_name,
          @imports,
          @dependency_graph = Normalizer.new(state).normalize
      end

      # The module package path.
      #
      # @return [Array<String>]
      attr_reader :package_path

      # Rules indexed by name.
      #
      # @return [Hash{String => Array<AST::Rule>}]
      attr_reader :rules_by_name

      # Import declarations.
      #
      # @return [Array<AST::Import>]
      attr_reader :imports

      # Dependency graph for rule evaluation ordering.
      #
      # @return [Hash{String => Array<String>}]
      attr_reader :dependency_graph

      # Fetch rules for a given name.
      #
      # @param name [String, Symbol] rule name
      # @return [Array<AST::Rule>] rules matching the name
      def lookup_rule(name)
        rules_by_name.fetch(name.to_s) { empty_rules }
      end

      # List all rule names.
      #
      # @return [Array<String>]
      def rule_names
        rules_by_name.keys
      end

      # Check whether a rule exists.
      #
      # @param name [String, Symbol] rule name
      # @return [Boolean] true when present
      # rubocop:disable Naming/PredicatePrefix
      def has_rule?(name)
        rules_by_name.key?(name.to_s)
      end
      # rubocop:enable Naming/PredicatePrefix

      # Normalizes compiled module inputs and freezes them for immutability.
      class Normalizer
        def initialize(state)
          @package_path = state.fetch(:package_path)
          @rules_by_name = state.fetch(:rules_by_name)
          @imports = state.fetch(:imports)
          @dependency_graph = state.fetch(:dependency_graph)
        end

        def normalize
          [
            package_path.dup.freeze,
            normalize_rules,
            imports.dup.freeze,
            normalize_dependency_graph
          ]
        end

        private

        attr_reader :package_path, :rules_by_name, :imports, :dependency_graph

        def normalize_rules
          rules_by_name.transform_values { |rules| rules.dup.freeze }.freeze
        end

        def normalize_dependency_graph
          dependency_graph.transform_values { |deps| deps.dup.freeze }.freeze
        end
      end

      private

      def empty_rules
        @empty_rules ||= begin
          empty = [] # @type var empty: Array[AST::Rule]
          empty.freeze
        end
      end

      private_constant :Normalizer
    end
  end
end
