# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Variable-name extraction from `some` destructuring patterns.
      module VariableCollectorHelpers
        # Variable names bound by a list of `some` targets (value positions only).
        def self.some_decl_names(variables)
          variables.flat_map { |variable| some_pattern_names(variable) }
        end

        # All variable names appearing in `some` targets, including object keys.
        # Keys are referenced but never bound, so they surface as unsafe when not
        # bound elsewhere (OPA rejects a variable object key in a pattern).
        def self.some_decl_all_names(variables)
          variables.flat_map { |variable| some_pattern_all_names(variable) }
        end

        def self.some_pattern_all_names(node)
          case node
          when AST::Variable then [node.name]
          when AST::ArrayLiteral then node.elements.flat_map { |element| some_pattern_all_names(element) }
          when AST::ObjectLiteral
            node.pairs.flat_map { |(key, value)| some_pattern_all_names(key) + some_pattern_all_names(value) }
          else []
          end
        end

        # Variable names bound by a single `some` target, recursing into array/object
        # destructuring patterns (value positions only; object keys are matched,
        # not bound).
        def self.some_pattern_names(node)
          case node
          when AST::Variable then [node.name]
          when AST::ArrayLiteral then node.elements.flat_map { |element| some_pattern_names(element) }
          when AST::ObjectLiteral then node.pairs.flat_map { |(_key, value)| some_pattern_names(value) }
          else []
          end
        end
      end
    end
  end
end
