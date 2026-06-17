# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Node-class dispatch tables and lookups for variable collection.
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
      end
    end
  end
end
