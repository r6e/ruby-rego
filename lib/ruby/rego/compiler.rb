# frozen_string_literal: true

require_relative "ast"
require_relative "compiled_module"
require_relative "errors"
require_relative "environment"
require_relative "evaluator/variable_collector"

module Ruby
  # Rego compilation helpers.
  module Rego
    # Compiles AST modules into indexed structures for evaluation.
    class Compiler
      # @param ast_module [AST::Module]
      # @return [CompiledModule]
      def compile(ast_module)
        rules_by_name = compile_rules(ast_module)
        package_path = ast_module.package.path
        dependency_graph = dependency_graph_builder.build(rules_by_name, package_path)
        artifacts = CompilationArtifacts.new(
          rules_by_name: rules_by_name,
          package_path: package_path,
          dependency_graph: dependency_graph
        )
        CompiledModuleBuilder.build(ast_module, artifacts)
      end

      # @param rules [Array<AST::Rule>]
      # @return [Hash{String => Array<AST::Rule>}]
      def index_rules(rules)
        rule_indexer.index(rules)
      end

      # @param rules [Array<AST::Rule>, Hash{String => Array<AST::Rule>}]
      # @return [void]
      def check_conflicts(rules)
        conflict_checker.check(rules)
      end

      # @param rule [AST::Rule]
      # @return [void]
      def check_safety(rule)
        safety_checker.check_rule(rule)
      end

      private

      def compile_rules(ast_module)
        rules_by_name = index_rules(ast_module.rules)
        check_conflicts(rules_by_name)
        safety_checker.check_rules(rules_by_name)
        rules_by_name
      end

      def rule_indexer
        @rule_indexer ||= RuleIndexer
      end

      def conflict_checker
        @conflict_checker ||= ConflictChecker.new
      end

      def safety_checker
        @safety_checker ||= SafetyChecker.new
      end

      def dependency_graph_builder
        @dependency_graph_builder ||= DependencyGraphBuilder.new
      end
    end

    # Bundles compiled module inputs.
    CompilationArtifacts = Struct.new(
      :rules_by_name,
      :package_path,
      :dependency_graph,
      keyword_init: true
    )

    # Groups rules with the same name for conflict checks.
    class RuleGroup
      # @param name [String]
      # @param rules [Array<AST::Rule>]
      def initialize(name:, rules:)
        @name = name
        @rules = rules
      end

      # @return [String]
      attr_reader :name

      # @return [Array<AST::Rule>]
      attr_reader :rules

      def validate(type_resolver)
        ensure_consistent_types(type_resolver)
        ensure_complete_rule_consistency
        ensure_function_arity
        ensure_single_default
      end

      def types(type_resolver)
        rules.map { |rule| type_resolver.type_for(rule) }.uniq
      end

      def complete_rules
        rules.select(&:complete?)
      end

      def value_rules
        complete_rules.reject(&:default_value).select do |rule|
          head = rule.head
          head && head[:value]
        end
      end

      def function_rules
        rules.select(&:function?)
      end

      def default_rules
        rules.select(&:default_value)
      end

      private

      def ensure_consistent_types(type_resolver)
        types = types(type_resolver)
        return if types.length <= 1

        raise CompilationError.new(
          "Conflicting rule types for #{name}: #{types.compact.join(", ")}",
          location: rules.first.location
        )
      end

      def ensure_complete_rule_consistency
        value_rule_list = value_rules
        return if value_rule_list.length <= 1

        raise CompilationError.new(
          "Conflicting complete rules for #{name}",
          location: value_rule_list.first.location
        )
      end

      def ensure_function_arity
        arities = function_arities
        return if arities.length <= 1

        raise CompilationError.new(
          "Conflicting function arity for #{name}: #{arities.sort.join(", ")}",
          location: function_rules.first.location
        )
      end

      def ensure_single_default
        defaults = default_rules
        return if defaults.length <= 1

        raise CompilationError.new(
          "Conflicting default rules for #{name}",
          location: defaults.first.location
        )
      end

      def function_arities
        rules = function_rules
        return [] if rules.empty?

        rules.map { |rule| Array(rule.head[:args]).length }.uniq
      end
    end

    # Indexes rules by their name for lookup.
    module RuleIndexer
      def self.index(rules)
        rules.group_by(&:name)
      end
    end

    # Resolves rule types for conflict checks.
    module RuleTypeResolver
      def self.type_for(rule)
        return :complete if rule.complete?
        return :partial_set if rule.partial_set?
        return :partial_object if rule.partial_object?
        return :function if rule.function?

        nil
      end
    end

    # Validates rule groups for compilation conflicts.
    class ConflictChecker
      def initialize(indexer: RuleIndexer, type_resolver: RuleTypeResolver)
        @indexer = indexer
        @type_resolver = type_resolver
      end

      def check(rules)
        rule_groups(rules).each { |group| group.validate(type_resolver) }
      end

      private

      attr_reader :indexer, :type_resolver

      def rule_groups(rules)
        grouped = rules.is_a?(Hash) ? rules : indexer.index(rules)
        grouped.map { |name, group| RuleGroup.new(name: name, rules: group) }
      end
    end

    # Builds compiled module instances.
    module CompiledModuleBuilder
      def self.build(ast_module, artifacts)
        CompiledModule.new(
          package_path: artifacts.package_path,
          rules_by_name: artifacts.rules_by_name,
          imports: ast_module.imports,
          dependency_graph: artifacts.dependency_graph
        )
      end
    end

    # Normalizes a rule head into reusable accessors.
    class RuleHead
      def initialize(head)
        head_hash = head.is_a?(Hash) ? head : {} # @type var head_hash: Hash[Symbol, untyped]
        @head = head_hash
      end

      def type
        head[:type]
      end

      def nodes
        return value_nodes if type == :complete
        return [head[:term]].compact if type == :partial_set
        return [head[:key], head[:value]].compact if type == :partial_object
        return function_nodes if type == :function

        []
      end

      def function_arg_names
        return [] unless type == :function

        function_arg_nodes.filter_map { |arg| arg.is_a?(AST::Variable) ? arg.name : nil }
      end

      private

      attr_reader :head

      def value_nodes
        value = head[:value]
        value ? [value] : []
      end

      def function_nodes
        args = Array(head[:args]).compact
        value = head[:value]
        value ? args + [value] : args
      end

      def function_arg_nodes
        args = head[:args]
        args.is_a?(Array) ? args : []
      end
    end

    # Validates rule safety for unbound variables.
    class SafetyChecker
      def initialize(
        bound_collector: Evaluator::BoundVariableCollector.new,
        variable_collector_class: Evaluator::VariableCollector,
        safe_names: Environment::RESERVED_NAMES + ["_"]
      )
        @bound_collector = bound_collector
        @variable_collector_class = variable_collector_class
        @safe_names = safe_names
      end

      def check_rules(rules_by_name)
        rules_by_name.values.flatten.each { |rule| check_rule(rule) }
      end

      def check_rule(rule)
        context = RuleSafetyContext.new(
          head: RuleHead.new(rule.head),
          bound_collector: bound_collector,
          variable_collector_class: variable_collector_class,
          safe_names: safe_names
        )
        RuleSafety.new(rule: rule, context: context).check
      end

      private

      attr_reader :bound_collector, :variable_collector_class, :safe_names
    end

    # Bundles dependencies for rule safety checks.
    RuleSafetyContext = Struct.new(
      :head,
      :bound_collector,
      :variable_collector_class,
      :safe_names,
      keyword_init: true
    )

    # Represents a safety check section.
    RuleSafetySection = Struct.new(:body, :head_nodes, keyword_init: true)

    # Runs safety checks for a single rule.
    class RuleSafety
      def initialize(rule:, context:)
        @rule = rule
        @context = context
      end

      def check
        check_body
        check_else_clause
      end

      private

      attr_reader :rule, :context

      def head
        context.head
      end

      def bound_collector
        context.bound_collector
      end

      def variable_collector_class
        context.variable_collector_class
      end

      def safe_names
        context.safe_names
      end

      def check_body
        check_section(RuleSafetySection.new(body: rule.body, head_nodes: head.nodes))
      end

      def check_else_clause
        section = else_section
        return unless section

        check_section(section)
      end

      def else_section
        clause = rule.else_clause
        return unless clause

        RuleSafetySection.new(body: clause[:body], head_nodes: else_nodes(clause))
      end

      def else_nodes(clause)
        nodes = head.nodes
        else_value = clause[:value]
        else_value ? nodes + [else_value] : nodes
      end

      def check_section(section)
        unbound = unbound_variables(section)
        return if unbound.empty?

        raise CompilationError.new(error_message(unbound), location: rule.location)
      end

      def unbound_variables(section)
        referenced_names(section) - bound_variables(section.body) - safe_names
      end

      def bound_variables(body)
        bound = bound_collector.collect_details(Array(body))[:all]
        bound.concat(head.function_arg_names)
        bound.uniq
      end

      def referenced_names(section)
        names = variable_collector_class.new.collect_literals(Array(section.body))
        Array(section.head_nodes).compact.each do |node|
          names.concat(variable_collector_class.new.collect(node))
        end
        names.uniq
      end

      def error_message(unbound)
        "Unsafe rule #{rule.name}: unbound variables #{unbound.sort.join(", ")}"
      end
    end

    # Captures rule metadata for dependency resolution.
    class DependencyContext
      # @param rule_names [Array<String>]
      # @param package_path [Array<String>]
      def initialize(rule_names:, package_path:)
        @rule_names = rule_names
        @package_path = package_path
      end

      # @return [Array<String>]
      attr_reader :rule_names

      # @return [Array<String>]
      attr_reader :package_path

      def package_depth
        @package_depth ||= package_path.length
      end

      def package_match?(keys)
        keys.length > package_depth && keys[0, package_depth] == package_path
      end

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
      def initialize(extractor: RuleDependencyExtractor.new)
        @extractor = extractor
      end

      def build(rules_by_name, package_path)
        context = DependencyContext.new(rule_names: rules_by_name.keys, package_path: package_path)
        DependencyGraph.new(rules_by_name: rules_by_name, context: context, extractor: extractor).build
      end

      private

      attr_reader :extractor
    end

    # Computes dependencies for each rule group.
    class DependencyGraph
      def initialize(rules_by_name:, context:, extractor:)
        @rules_by_name = rules_by_name
        @context = context
        @extractor = extractor
      end

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
      def initialize(
        reference_walker: ReferenceWalker.new,
        resolver: RuleReferenceResolver.new,
        node_extractor_class: RuleNodeExtractor
      )
        @reference_walker = reference_walker
        @resolver = resolver
        @node_extractor_class = node_extractor_class
      end

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
      def initialize(rule)
        @rule = rule
        @else_clause = rule.else_clause
      end

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

      def initialize(children_extractors: NODE_CHILDREN, handlers: NODE_HANDLERS)
        @children_extractors = children_extractors
        @handlers = handlers
      end

      def references(nodes)
        refs = [] # @type var refs: Array[AST::Reference]
        each_reference(nodes) { |ref| refs << ref }
        refs
      end

      def each_reference(nodes, &block)
        return enum_for(:each_reference, nodes) unless block

        Array(nodes).each { |node| walk(node, &block) }
      end

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
      def initialize(key_extractor: ReferenceKeyExtractor.new, data_root: "data")
        @key_extractor = key_extractor
        @data_root = data_root
      end

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

      def initialize(extractors: DEFAULT_EXTRACTORS)
        @extractors = extractors
      end

      def extract(segment)
        extractor = extractors[segment.class]
        return nil unless extractor

        extractor.call(segment, self)
      end

      private

      attr_reader :extractors
    end

    private_constant :RuleGroup,
                     :RuleIndexer,
                     :RuleTypeResolver,
                     :ConflictChecker,
                     :CompilationArtifacts,
                     :CompiledModuleBuilder,
                     :RuleHead,
                     :SafetyChecker,
                     :RuleSafetyContext,
                     :RuleSafetySection,
                     :RuleSafety,
                     :DependencyContext,
                     :DependencyGraphBuilder,
                     :DependencyGraph,
                     :RuleDependencyExtractor,
                     :RuleNodeExtractor,
                     :ReferenceWalker,
                     :RuleReferenceResolver,
                     :ReferenceKeyExtractor
  end
end
