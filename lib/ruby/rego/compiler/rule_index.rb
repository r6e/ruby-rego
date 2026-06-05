# frozen_string_literal: true

require_relative "../compiled_module"
require_relative "../errors"

module Ruby
  # Rego compilation helpers.
  module Rego
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
        # NOTE: Complete-rule conflicts are resolved during evaluation.
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

    private_constant :RuleGroup, :RuleIndexer, :RuleTypeResolver, :ConflictChecker,
                     :CompiledModuleBuilder
  end
end
