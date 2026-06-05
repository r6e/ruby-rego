# frozen_string_literal: true

require_relative "../ast"
module Ruby
  # Rego compilation helpers.
  module Rego
    # Captures rule metadata for dependency resolution.
    class DependencyContext
      # Create a dependency context.
      #
      # @param rule_names [Array<String>] known rule names
      # @param package_path [Array<String>] module package path
      def initialize(rule_names:, package_path:)
        @rule_names = rule_names
        @package_path = package_path
      end

      # Rule names to resolve.
      #
      # @return [Array<String>]
      attr_reader :rule_names

      # Package path for the module.
      #
      # @return [Array<String>]
      attr_reader :package_path

      # Package path depth.
      #
      # @return [Integer]
      def package_depth
        @package_depth ||= package_path.length
      end

      # Check whether a reference path matches the package prefix.
      #
      # @param keys [Array<String>]
      # @return [Boolean]
      def package_match?(keys)
        keys.length > package_depth && keys[0, package_depth] == package_path
      end

      # Resolve a rule name from a reference key path.
      #
      # @param keys [Array<String>]
      # @return [String, nil]
      def resolve_rule_name(keys)
        package_candidate = package_candidate(keys)
        return package_candidate if package_candidate

        direct_candidate(keys)
      end

      private

      def package_candidate(keys)
        return nil unless package_match?(keys)

        rule_name_for(keys[package_depth])
      end

      def direct_candidate(keys)
        rule_name_for(keys.first)
      end

      def rule_name_for(value)
        candidate = value.to_s
        rule_names.include?(candidate) ? candidate : nil
      end
    end

    # Builds dependency graphs for compiled modules.
    class DependencyGraphBuilder
      # Create a dependency graph builder.
      #
      # @param extractor [RuleDependencyExtractor]
      def initialize(extractor: RuleDependencyExtractor.new)
        @extractor = extractor
      end

      # Build a dependency graph for a compiled module.
      #
      # @param rules_by_name [Hash{String => Array<AST::Rule>}]
      # @param package_path [Array<String>]
      # @return [Hash{String => Array<String>}]
      def build(rules_by_name, package_path)
        context = DependencyContext.new(rule_names: rules_by_name.keys, package_path: package_path)
        DependencyGraph.new(rules_by_name: rules_by_name, context: context, extractor: extractor).build
      end

      private

      attr_reader :extractor
    end

    # Computes dependencies for each rule group.
    class DependencyGraph
      # Create a dependency graph for a module.
      #
      # @param rules_by_name [Hash{String => Array<AST::Rule>}]
      # @param context [DependencyContext]
      # @param extractor [RuleDependencyExtractor]
      def initialize(rules_by_name:, context:, extractor:)
        @rules_by_name = rules_by_name
        @context = context
        @extractor = extractor
      end

      # Build the dependency graph.
      #
      # @return [Hash{String => Array<String>}]
      def build
        rules_by_name.transform_values { |rules| dependencies_for(rules) }
      end

      private

      attr_reader :rules_by_name, :context, :extractor

      def dependencies_for(rules)
        rules.flat_map { |rule| extractor.dependencies_for(rule, context) }.uniq
      end
    end

    # Extracts dependency names for a rule.
    class RuleDependencyExtractor
      # Create a dependency extractor.
      #
      # @param reference_walker [ReferenceWalker]
      # @param resolver [RuleReferenceResolver]
      # @param node_extractor_class [Class]
      def initialize(
        reference_walker: ReferenceWalker.new,
        resolver: RuleReferenceResolver.new,
        node_extractor_class: RuleNodeExtractor
      )
        @reference_walker = reference_walker
        @resolver = resolver
        @node_extractor_class = node_extractor_class
      end

      # Extract referenced rule names for a rule.
      #
      # @param rule [AST::Rule]
      # @param context [DependencyContext]
      # @return [Array<String>]
      def dependencies_for(rule, context)
        nodes = node_extractor_class.new(rule).nodes
        reference_walker
          .references(nodes)
          .filter_map { |ref| resolver.resolve(ref, context) }
          .uniq
      end

      private

      attr_reader :reference_walker, :resolver, :node_extractor_class
    end

    # Collects AST nodes to analyze rule dependencies.
    class RuleNodeExtractor
      # Create a node extractor for a rule.
      #
      # @param rule [AST::Rule]
      def initialize(rule)
        @rule = rule
        @else_clause = rule.else_clause
      end

      # Gather nodes that contribute to dependency analysis.
      #
      # @return [Array<AST::Base>]
      def nodes
        base_nodes + else_nodes
      end

      private

      attr_reader :rule, :else_clause

      def base_nodes
        RuleHead.new(rule.head).nodes + Array(rule.body)
      end

      def else_nodes
        return [] unless else_clause

        nodes = Array(else_clause[:body])
        else_value = else_clause[:value]
        else_value ? nodes + [else_value] : nodes
      end
    end

    # Walks AST nodes and yields reference nodes.
    class ReferenceWalker
      NODE_CHILDREN = {
        AST::Reference => ->(node) { [node.base] + node.path.map(&:value) },
        AST::BinaryOp => ->(node) { [node.left, node.right] },
        AST::UnaryOp => ->(node) { [node.operand] },
        AST::ArrayLiteral => :elements.to_proc,
        AST::SetLiteral => :elements.to_proc,
        AST::ObjectLiteral => lambda do |node|
          node.pairs.flat_map { |key_node, value_node| [key_node, value_node] }
        end,
        AST::ArrayComprehension => ->(node) { [node.term] + Array(node.body) },
        AST::SetComprehension => ->(node) { [node.term] + Array(node.body) },
        AST::ObjectComprehension => lambda do |node|
          key_node, value_node = node.term
          [key_node, value_node] + Array(node.body)
        end,
        AST::QueryLiteral => lambda do |node|
          modifier_nodes = node.with_modifiers.flat_map { |modifier| [modifier.target, modifier.value] }
          [node.expression] + modifier_nodes
        end,
        AST::WithModifier => ->(node) { [node.target, node.value] },
        AST::SomeDecl => ->(node) { Array(node.variables) + [node.collection].compact },
        AST::Every => lambda do |node|
          [node.key_var, node.value_var, node.domain].compact + Array(node.body)
        end,
        AST::Call => ->(node) { [node.name] + node.args }
      }.freeze
      NODE_HANDLERS = {
        AST::Reference => lambda do |node, walker, &block|
          block.call(node)
          walker.walk_children(node, &block)
        end
      }.freeze

      # Create a reference walker.
      #
      # @param children_extractors [Hash{Class => Proc}]
      # @param handlers [Hash{Class => Proc}]
      def initialize(children_extractors: NODE_CHILDREN, handlers: NODE_HANDLERS)
        @children_extractors = children_extractors
        @handlers = handlers
      end

      # Collect references from a set of nodes.
      #
      # @param nodes [Array<AST::Base>]
      # @return [Array<AST::Reference>]
      def references(nodes)
        refs = [] # @type var refs: Array[AST::Reference]
        each_reference(nodes) { |ref| refs << ref }
        refs
      end

      # Yield each reference found in the nodes.
      #
      # @param nodes [Array<AST::Base>]
      # @yieldparam reference [AST::Reference]
      # @return [Enumerator, void]
      def each_reference(nodes, &block)
        return enum_for(:each_reference, nodes) unless block

        Array(nodes).each { |node| walk(node, &block) }
      end

      # Walk child nodes of a node.
      #
      # @param node [AST::Base]
      # @yieldparam reference [AST::Reference]
      # @return [void]
      def walk_children(node, &block)
        children_for(node).each { |child| walk(child, &block) }
      end

      private

      attr_reader :children_extractors, :handlers

      def walk(node, &)
        handler = handlers[node.class]
        return handler.call(node, self, &) if handler

        walk_children(node, &)
      end

      def children_for(node)
        extractor = children_extractors[node.class]
        return [] unless extractor

        Array(extractor.call(node))
      end
    end

    # Resolves rule names referenced via data paths.
    class RuleReferenceResolver
      # Create a reference resolver.
      #
      # @param key_extractor [ReferenceKeyExtractor]
      # @param data_root [String]
      def initialize(key_extractor: ReferenceKeyExtractor.new, data_root: "data")
        @key_extractor = key_extractor
        @data_root = data_root
      end

      # Resolve a rule name from a reference node.
      #
      # @param ref [AST::Reference]
      # @param context [DependencyContext]
      # @return [String, nil]
      def resolve(ref, context)
        base = ref.base
        return nil unless base.is_a?(AST::Variable) && base.name == data_root

        keys = reference_keys(ref.path)
        return nil if keys.empty?

        context.resolve_rule_name(keys)
      end

      private

      attr_reader :key_extractor, :data_root

      def reference_keys(path)
        keys = path.map { |segment| key_extractor.extract(segment) }
        keys.any?(&:nil?) ? [] : keys
      end
    end

    # Extracts scalar keys from reference segments.
    class ReferenceKeyExtractor
      DEFAULT_EXTRACTORS = {
        AST::DotRefArg => ->(segment, extractor) { extractor.extract(segment.value) },
        AST::BracketRefArg => ->(segment, extractor) { extractor.extract(segment.value) },
        AST::StringLiteral => ->(segment, _extractor) { segment.value },
        AST::NumberLiteral => ->(segment, _extractor) { segment.value },
        AST::BooleanLiteral => ->(segment, _extractor) { segment.value },
        AST::NullLiteral => ->(_segment, _extractor) {},
        String => ->(segment, _extractor) { segment },
        Symbol => ->(segment, _extractor) { segment }
      }.freeze

      # Create a key extractor.
      #
      # @param extractors [Hash{Class => Proc}]
      def initialize(extractors: DEFAULT_EXTRACTORS)
        @extractors = extractors
      end

      # Extract a scalar key from a reference segment.
      #
      # @param segment [Object]
      # @return [Object, nil]
      def extract(segment)
        extractor = extractors[segment.class]
        return nil unless extractor

        extractor.call(segment, self)
      end

      private

      attr_reader :extractors
    end
    private_constant :DependencyContext, :DependencyGraphBuilder, :DependencyGraph,
                     :RuleDependencyExtractor, :RuleNodeExtractor, :ReferenceWalker,
                     :RuleReferenceResolver, :ReferenceKeyExtractor
  end
end
