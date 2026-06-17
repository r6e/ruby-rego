# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
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
          VariableCollectorHelpers.some_decl_all_names(node.variables).each { |name| add_name(name) }
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

require_relative "variable_collector/dispatch_tables"
require_relative "variable_collector/pattern_names"
require_relative "variable_collector/bound_variable_collector"
