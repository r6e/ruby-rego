# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Shared traversal helpers for variable collection.
      module VariableCollectorHelpers
        NODE_COLLECTORS = {
          AST::Variable => ->(node, collector) { collector.send(:add_name, node.name) },
          AST::SomeDecl => ->(node, collector) { collector.send(:collect_some_decl, node) },
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
          AST::Call => lambda do |node|
            call_name = node.name
            node.args.dup.tap { |args| args.unshift(call_name) if call_name.is_a?(AST::Reference) }
          end
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
          @names = [] # @type var @names: Array[String]
        end

        # @param literals [Array<Object>]
        # @return [Array<String>]
        def collect(literals)
          Array(literals).each { |literal| collect_from_literal(literal) }
          names.uniq
        end

        private

        attr_reader :names

        def collect_from_literal(literal)
          case literal
          in AST::SomeDecl[variables:]
            variables.each { |variable| names << variable.name }
          in AST::QueryLiteral[expression:]
            collect_from_expression(expression)
          else
            nil
          end
        end

        def collect_from_expression(expression)
          case expression
          in AST::BinaryOp[operator:, left:, right:]
            return unless %i[assign unify].include?(operator)

            collect_all_variables(left)
            collect_all_variables(right) if operator == :unify
          else
            nil
          end
        end

        def collect_all_variables(node)
          return unless node
          return names << node.name if node.is_a?(AST::Variable)
          return if VariableCollectorHelpers.comprehension_node?(node)

          VariableCollectorHelpers.children_for(node).each do |child|
            collect_all_variables(child)
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
