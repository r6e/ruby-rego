# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
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
            VariableCollectorHelpers.some_decl_names(variables).each { |name| explicit_names << name }
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
          # An object pattern binds value positions only. A variable key is not
          # bound by the pattern (OPA rejects it as unsafe unless bound elsewhere).
          return collect_object_value_variables(node, target) if node.is_a?(AST::ObjectLiteral)

          VariableCollectorHelpers.children_for(node).each do |child|
            collect_all_variables(child, target)
          end
        end

        def collect_object_value_variables(node, target)
          node.pairs.each { |(_key, value)| collect_all_variables(value, target) }
        end
      end
    end
  end
end
