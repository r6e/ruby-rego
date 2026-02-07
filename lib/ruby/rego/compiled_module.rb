# frozen_string_literal: true

module Ruby
  module Rego
    # Bundles compiled rule metadata for fast evaluation.
    class CompiledModule
      # @param package_path [Array<String>]
      # @param rules_by_name [Hash{String => Array<AST::Rule>}]
      # @param imports [Array<AST::Import>]
      # @param dependency_graph [Hash{String => Array<String>}]
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

      # @return [Array<String>]
      attr_reader :package_path

      # @return [Hash{String => Array<AST::Rule>}]
      attr_reader :rules_by_name

      # @return [Array<AST::Import>]
      attr_reader :imports

      # @return [Hash{String => Array<String>}]
      attr_reader :dependency_graph

      # @param name [String, Symbol]
      # @return [Array<AST::Rule>]
      def lookup_rule(name)
        rules_by_name.fetch(name.to_s) { empty_rules }
      end

      # @return [Array<String>]
      def rule_names
        rules_by_name.keys
      end

      # @param name [String, Symbol]
      # @return [Boolean]
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
