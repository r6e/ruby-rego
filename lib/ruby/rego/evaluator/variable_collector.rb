# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Shared traversal helpers for variable collection.
      module VariableCollectorHelpers
        NODE_COLLECTORS = {
          AST::Variable => ->(node, collector) { collector.send(:add_name, node.name) },
          AST::SomeDecl => ->(node, collector) { collector.send(:collect_some_decl, node) },
          AST::Every => ->(node, collector) { collector.send(:collect_every, node) },
          AST::QueryLiteral => ->(node, collector) { collector.send(:collect_node, node.expression) },
          AST::ArrayComprehension => lambda do |node, collector|
            collector.send(:collect_comprehension, [node.term], node.body)
          end,
          AST::SetComprehension => lambda do |node, collector|
            collector.send(:collect_comprehension, [node.term], node.body)
          end,
          AST::ObjectComprehension => lambda do |node, collector|
            key_node, value_node = node.term
            collector.send(:collect_comprehension, [key_node, value_node], node.body)
          end
        }.freeze

        CHILDREN_EXTRACTORS = {
          AST::Reference => ->(node) { [node.base] + node.path.map(&:value) },
          AST::BinaryOp => ->(node) { [node.left, node.right] },
          AST::UnaryOp => ->(node) { [node.operand] },
          AST::ArrayLiteral => :elements.to_proc,
          AST::SetLiteral => :elements.to_proc,
          AST::ObjectLiteral => lambda do |node|
            node.pairs.flat_map { |key_node, value_node| [key_node, value_node] }
          end,
          AST::ArrayComprehension => ->(node) { [node.term] },
          AST::SetComprehension => ->(node) { [node.term] },
          AST::ObjectComprehension => lambda do |node|
            key_node, value_node = node.term
            [key_node, value_node]
          end,
          AST::Call => ->(node) { node.args.dup }
        }.freeze

        def self.collector_for(node)
          NODE_COLLECTORS[node.class]
        end

        def self.children_for(node)
          extractor = CHILDREN_EXTRACTORS[node.class]
          return [] unless extractor

          extractor.call(node)
        end

        def self.comprehension_node?(node)
          node.is_a?(AST::ArrayComprehension) || node.is_a?(AST::SetComprehension) || node.is_a?(AST::ObjectComprehension)
        end
      end

      # Collects variable names that become bound inside query bodies.
      class BoundVariableCollector
        def initialize
          @explicit_names = [] # @type var @explicit_names: Array[String]
          @unify_names = [] # @type var @unify_names: Array[String]
        end

        # @param literals [Array<Object>]
        # @return [Array<String>]
        def collect(literals)
          collect_details(literals)[:all]
        end

        # @param literals [Array<Object>]
        # @return [Hash<Symbol, Array<String>>]
        # :reek:TooManyStatements
        def collect_details(literals)
          reset
          Array(literals).each { |literal| collect_from_literal(literal) }
          explicit = explicit_names.uniq
          unification = unify_names.uniq
          { explicit: explicit, unification: unification, all: (explicit + unification).uniq }
        end

        private

        attr_reader :explicit_names, :unify_names

        def reset
          explicit_names.clear
          unify_names.clear
        end

        def collect_from_literal(literal)
          case literal
          in AST::SomeDecl[variables:]
            variables.each { |variable| explicit_names << variable.name }
          in AST::QueryLiteral[expression:]
            collect_from_expression(expression)
          else
            nil
          end
        end

        # :reek:FeatureEnvy
        # :reek:TooManyStatements
        def collect_from_expression(expression)
          return unless expression.is_a?(AST::BinaryOp)

          operator = expression.operator
          left = expression.left
          collect_explicit_variables(left) if operator == :assign
          return unless operator == :unify

          collect_unification_variables(left)
          collect_unification_variables(expression.right)
        end

        def collect_explicit_variables(node)
          collect_all_variables(node, explicit_names)
        end

        def collect_unification_variables(node)
          collect_all_variables(node, unify_names)
        end

        # :reek:FeatureEnvy
        def collect_all_variables(node, target)
          return unless node
          return target << node.name if node.is_a?(AST::Variable)
          return if VariableCollectorHelpers.comprehension_node?(node)

          VariableCollectorHelpers.children_for(node).each do |child|
            collect_all_variables(child, target)
          end
        end
      end

      # Collects variable names referenced in expressions and query literals.
      # :reek:TooManyMethods
      class VariableCollector
        def initialize
          @names = [] # @type var @names: Array[String]
          @local_scopes = [] # @type var @local_scopes: Array[Array[String]]
        end

        # @param node [Object]
        # @return [Array<String>]
        def collect(node)
          collect_node(node)
          names
        end

        # @param literals [Array<Object>]
        # @return [Array<String>]
        def collect_literals(literals)
          Array(literals).each { |literal| collect_node(literal) }
          names
        end

        private

        attr_reader :names

        def collect_node(node)
          return unless node

          handler = VariableCollectorHelpers.collector_for(node)
          return handler.call(node, self) if handler

          VariableCollectorHelpers.children_for(node).each { |child| collect_node(child) }
        end

        def collect_comprehension(term_nodes, body_literals)
          locals = BoundVariableCollector.new.collect(body_literals)
          with_locals(locals) { collect_comprehension_body(term_nodes, body_literals) }
        end

        def collect_comprehension_body(term_nodes, body_literals)
          term_nodes.each { |term_node| collect_node(term_node) }
          Array(body_literals).each { |literal| collect_node(literal) }
        end

        def collect_some_decl(node)
          node.variables.each { |variable| add_name(variable.name) }
          collection = node.collection
          collect_node(collection) if collection
        end

        # :reek:TooManyStatements
        def collect_every(node)
          collect_node(node.domain)
          body = Array(node.body)
          locals = BoundVariableCollector.new.collect(body)
          locals.concat(every_variable_names(node))
          with_locals(locals.uniq) { body.each { |literal| collect_node(literal) } }
        end

        # :reek:UtilityFunction
        def every_variable_names(node)
          [node.key_var, node.value_var].compact.map(&:name)
        end

        def add_name(name)
          return if local_name?(name)

          names << name
        end

        def with_locals(names)
          @local_scopes << names
          yield
        ensure
          @local_scopes.pop
        end

        def local_name?(name)
          @local_scopes.any? { |scope| scope.include?(name) }
        end
      end
    end
  end
end
