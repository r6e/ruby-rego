# frozen_string_literal: true

require_relative "../ast"
require_relative "../call_name"
require_relative "../errors"
require_relative "../environment"
require_relative "../builtins/registry"
require_relative "../evaluator/variable_collector"
require_relative "rule_head"

module Ruby
  # Rego compilation helpers.
  module Rego
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
      def check_rules(rules_by_name, safe_names: @safe_names)
        rules_by_name.values.flatten.each { |rule| check_rule(rule, safe_names: safe_names) }
      end

      # Validate a single rule for unbound variables.
      #
      # @param rule [AST::Rule]
      # @return [void]
      def check_rule(rule, safe_names: @safe_names)
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

    DEFAULT_RULE_CHILD_NODE_EXTRACTORS = {
      AST::BinaryOp => ->(node) { [node.left, node.right] },
      AST::UnaryOp => ->(node) { [node.operand] },
      AST::ArrayLiteral => :elements.to_proc,
      AST::SetLiteral => :elements.to_proc,
      AST::ObjectLiteral => lambda do |node|
        node.pairs.flat_map { |key_node, value_node| [key_node, value_node] }
      end,
      AST::ArrayComprehension => lambda do |node|
        term = node.term
        body = Array(node.body)
        [term] + body
      end,
      AST::SetComprehension => lambda do |node|
        term = node.term
        body = Array(node.body)
        [term] + body
      end,
      AST::ObjectComprehension => lambda do |node|
        key_node, value_node = node.term
        body = Array(node.body)
        [key_node, value_node] + body
      end,
      AST::Call => ->(node) { [node.name] + node.args },
      AST::QueryLiteral => ->(node) { [node.expression] + node.with_modifiers },
      AST::Every => lambda do |node|
        body = Array(node.body)
        [node.key_var, node.value_var, node.domain] + body
      end,
      AST::SomeDecl => ->(node) { node.variables + Array(node.collection) },
      AST::WithModifier => ->(node) { [node.target, node.value] },
      AST::TemplateString => :parts.to_proc
    }.freeze

    # Resolves builtin call names for default rule validation.
    module DefaultRuleCallName
      module_function

      def call_name(node)
        CallName.call_name(node)
      end

      def reference_call_name(reference)
        CallName.reference_call_name(reference)
      end

      def reference_base_name(reference)
        CallName.reference_base_name(reference)
      end
      private_class_method :reference_base_name

      def reference_call_segments(path)
        CallName.reference_call_segments(path)
      end
      private_class_method :reference_call_segments

      def dot_ref_segment_value(segment)
        CallName.dot_ref_segment_value(segment)
      end
      private_class_method :dot_ref_segment_value
    end

    # Validates default rule values for groundness.
    class DefaultRuleValidator
      def initialize(
        child_node_extractors: DEFAULT_RULE_CHILD_NODE_EXTRACTORS,
        builtin_registry: Builtins::BuiltinRegistry.instance
      )
        @child_node_extractors = child_node_extractors
        _ = builtin_registry
      end

      # :reek:TooManyStatements
      def check(rules_by_name)
        Array(rules_by_name.values).flatten.each do |rule|
          value = rule.default_value
          next unless value
          next if comprehension_value?(value)
          next unless contains_variable_or_reference?(value)

          raise CompilationError.new(
            "Default rule values must be ground (no variables, references, or calls)",
            location: rule.location
          )
        end
      end

      private

      attr_reader :child_node_extractors

      # :reek:TooManyStatements
      def contains_variable_or_reference?(node)
        return false unless node
        return true if node.is_a?(AST::Variable)
        return true if node.is_a?(AST::Reference)
        return true if node.is_a?(AST::Call)
        return false if comprehension_value?(node)

        child_nodes(node).any? do |child|
          contains_variable_or_reference?(child)
        end
      end

      # :reek:UtilityFunction
      def comprehension_value?(value)
        value.is_a?(AST::ArrayComprehension) ||
          value.is_a?(AST::SetComprehension) ||
          value.is_a?(AST::ObjectComprehension)
      end

      def child_nodes(node)
        extractor = child_node_extractors[node.class]
        return [] unless extractor

        extractor.call(node)
      end
    end

    # Bundles dependencies for rule safety checks.
    RuleSafetyContext = Struct.new(
      :head,
      :bound_collector,
      :variable_collector_class,
      :safe_names
    )

    # Represents a safety check section.
    RuleSafetySection = Struct.new(:body, :head_nodes)

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
    private_constant :SafetyChecker, :RuleSafetyContext, :RuleSafetySection, :RuleSafety
  end
end
