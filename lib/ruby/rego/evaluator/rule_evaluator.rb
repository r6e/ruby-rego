# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Evaluates rule bodies and heads.
      class RuleEvaluator
        # @param environment [Environment]
        # @param expression_evaluator [ExpressionEvaluator]
        def initialize(environment:, expression_evaluator:)
          @environment = environment
          @expression_evaluator = expression_evaluator
        end

        # @param rules [Array<AST::Rule>]
        # @return [Value]
        def evaluate_group(rules)
          return UndefinedValue.new if rules.empty?

          first_rule = rules.first
          return evaluate_partial_set_rules(rules) if first_rule.partial_set?
          return evaluate_partial_object_rules(rules) if first_rule.partial_object?

          evaluate_complete_rules(rules)
        end

        # @param rule [AST::Rule]
        # @return [Value, Array]
        def evaluate_rule(rule)
          environment.push_scope
          return UndefinedValue.new unless body_succeeds?(rule.body)

          evaluate_rule_value(rule.head)
        ensure
          environment.pop_scope
        end

        private

        attr_reader :environment, :expression_evaluator

        def evaluate_partial_set_rules(rules)
          values = rules.map { |rule| evaluate_rule(rule) }
                        .reject { |value| value.is_a?(UndefinedValue) }
          return UndefinedValue.new if values.empty?

          SetValue.new(values)
        end

        def evaluate_partial_object_rules(rules)
          hash = partial_object_pairs(rules)
          hash.empty? ? UndefinedValue.new : ObjectValue.new(hash)
        end

        def partial_object_pairs(rules)
          rules.filter_map do |rule|
            pair = evaluate_rule(rule)
            pair.is_a?(UndefinedValue) ? nil : pair
          end.to_h
        end

        def evaluate_complete_rules(rules)
          value = evaluate_non_default_rules(rules.reject(&:default_value))
          return value if value

          default_rule = rules.find(&:default_value)
          return UndefinedValue.new unless default_rule

          expression_evaluator.evaluate(default_rule.default_value)
        end

        def evaluate_partial_object_value(head)
          key = expression_evaluator.evaluate(head[:key])
          value = expression_evaluator.evaluate(head[:value])
          return UndefinedValue.new if key.is_a?(UndefinedValue) || value.is_a?(UndefinedValue)

          [key.to_ruby, value]
        end

        def evaluate_complete_rule_value(head)
          value_node = head[:value]
          return expression_evaluator.evaluate(value_node) if value_node

          BooleanValue.new(true)
        end

        def body_succeeds?(body)
          literals = Array(body)
          return true if literals.empty?

          literals.all? { |literal| query_literal_truthy?(literal) }
        end

        def evaluate_non_default_rules(rules)
          rules.each do |rule|
            value = evaluate_rule(rule)
            return value unless value.undefined?
          end

          nil
        end

        def query_literal_truthy?(literal)
          case literal
          when AST::QueryLiteral
            query_expression_truthy?(literal)
          when AST::SomeDecl
            some_decl_truthy?(literal)
          else
            false
          end
        end

        def query_expression_truthy?(literal)
          expression_evaluator.evaluate(literal.expression).truthy?
        end

        def evaluate_rule_value(head)
          case head[:type]
          when :complete
            evaluate_complete_rule_value(head)
          when :partial_set
            expression_evaluator.evaluate(head[:term])
          when :partial_object
            evaluate_partial_object_value(head)
          else
            UndefinedValue.new
          end
        end

        def some_decl_truthy?(literal)
          literal.variables.each do |variable|
            name = variable.name
            next if name == "_"

            environment.bind(name, UndefinedValue.new)
          end
          true
        end
      end
    end
  end
end
