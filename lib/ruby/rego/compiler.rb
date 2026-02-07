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
      # Compile an AST module into a compiled module.
      #
      # @param ast_module [AST::Module] parsed module
      # @return [CompiledModule] compiled module
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

      # Index rules by name.
      #
      # @param rules [Array<AST::Rule>] rules to index
      # @return [Hash{String => Array<AST::Rule>}] rules indexed by name
      def index_rules(rules)
        rule_indexer.index(rules)
      end

      # Validate a rule set for conflicts.
      #
      # @param rules [Array<AST::Rule>, Hash{String => Array<AST::Rule>}] rules to check
      # @return [void]
      def check_conflicts(rules)
        conflict_checker.check(rules)
      end

      # Validate a rule for safety (unbound variables).
      #
      # @param rule [AST::Rule] rule to check
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
      # Create a rule group.
      #
      # @param name [String] rule name
      # @param rules [Array<AST::Rule>] rules sharing the name
      def initialize(name:, rules:)
        @name = name
        @rules = rules
      end

      # The rule name for the group.
      #
      # @return [String]
      attr_reader :name

      # Rules in the group.
      #
      # @return [Array<AST::Rule>]
      attr_reader :rules

      # Validate the group against type and conflict rules.
      #
      # @param type_resolver [#type_for]
      # @return [void]
      def validate(type_resolver)
        ensure_consistent_types(type_resolver)
        ensure_complete_rule_consistency
        ensure_function_arity
        ensure_single_default
      end

      # Resolve the unique rule types present in the group.
      #
      # @param type_resolver [#type_for]
      # @return [Array<Symbol, nil>]
      def types(type_resolver)
        rules.map { |rule| type_resolver.type_for(rule) }.uniq
      end

      # Select complete rules.
      #
      # @return [Array<AST::Rule>]
      def complete_rules
        rules.select(&:complete?)
      end

      # Select complete rules with explicit values.
      #
      # @return [Array<AST::Rule>]
      def value_rules
        complete_rules.reject(&:default_value).select do |rule|
          head = rule.head
          head && head[:value]
        end
      end

      # Select function rules.
      #
      # @return [Array<AST::Rule>]
      def function_rules
        rules.select(&:function?)
      end

      # Select default rules.
      #
      # @return [Array<AST::Rule>]
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
      # Index rules by name.
      #
      # @param rules [Array<AST::Rule>]
      # @return [Hash{String => Array<AST::Rule>}]
      def self.index(rules)
        rules.group_by(&:name)
      end
    end

    # Resolves rule types for conflict checks.
    module RuleTypeResolver
      # Determine the rule type for conflict checks.
      #
      # @param rule [AST::Rule]
      # @return [Symbol, nil]
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
      # Create a conflict checker.
      #
      # @param indexer [#index] rule indexer
      # @param type_resolver [#type_for] rule type resolver
      def initialize(indexer: RuleIndexer, type_resolver: RuleTypeResolver)
        @indexer = indexer
        @type_resolver = type_resolver
      end

      # Check for conflicts in a rule set.
      #
      # @param rules [Array<AST::Rule>, Hash{String => Array<AST::Rule>}]
      # @return [void]
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
      # Build a compiled module from AST and artifacts.
      #
      # @param ast_module [AST::Module]
      # @param artifacts [CompilationArtifacts]
      # @return [CompiledModule]
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
      # Create a wrapper for a rule head hash.
      #
      # @param head [Hash, nil] rule head data
      def initialize(head)
        head_hash = head.is_a?(Hash) ? head : {} # @type var head_hash: Hash[Symbol, untyped]
        @head = head_hash
      end

      # Return the rule head type.
      #
      # @return [Symbol, nil]
      def type
        head[:type]
      end

      # Return AST nodes that appear in the rule head.
      #
      # @return [Array<AST::Base>]
      def nodes
        return value_nodes if type == :complete
        return [head[:term]].compact if type == :partial_set
        return [head[:key], head[:value]].compact if type == :partial_object
        return function_nodes if type == :function

        []
      end

      # Return function argument names for a function rule head.
      #
      # @return [Array<String>]
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
      # Create a safety checker.
      #
      # @param bound_collector [Evaluator::BoundVariableCollector]
      # @param variable_collector_class [Class]
      # @param safe_names [Array<String>]
      def initialize(
        bound_collector: Evaluator::BoundVariableCollector.new,
        variable_collector_class: Evaluator::VariableCollector,
        safe_names: Environment::RESERVED_NAMES + ["_"]
      )
        @bound_collector = bound_collector
        @variable_collector_class = variable_collector_class
        @safe_names = safe_names
      end

      # Validate all rules in the provided index.
      #
      # @param rules_by_name [Hash{String => Array<AST::Rule>}]
      # @return [void]
      def check_rules(rules_by_name)
        rules_by_name.values.flatten.each { |rule| check_rule(rule) }
      end

      # Validate a single rule for unbound variables.
      #
      # @param rule [AST::Rule]
      # @return [void]
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
      # Create a safety checker for a specific rule.
      #
      # @param rule [AST::Rule]
      # @param context [RuleSafetyContext]
      def initialize(rule:, context:)
        @rule = rule
        @context = context
      end

      # Perform safety checks on the rule body and else clause.
      #
      # @return [void]
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
