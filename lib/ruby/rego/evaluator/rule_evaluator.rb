# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Evaluates rule bodies and heads.
      # rubocop:disable Metrics/ClassLength
      # :reek:TooManyMethods
      # :reek:DataClump
      class RuleEvaluator
        # Bundles query evaluation state to minimize parameter passing.
        QueryContext = Struct.new(:literals, :env, keyword_init: true)

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
        # :reek:FeatureEnvy
        def evaluate_rule(rule)
          values = rule_body_values(rule)
          values.empty? ? UndefinedValue.new : values.first
        end

        # @param literals [Array<Object>]
        # @param env [Environment]
        # @return [Enumerator]
        # @api private
        def query_solutions(literals, env = environment)
          eval_query(literals, env)
        end

        private

        attr_reader :environment, :expression_evaluator

        def evaluate_partial_set_rules(rules)
          values = rules.flat_map { |rule| rule_body_values(rule) }
          return UndefinedValue.new if values.empty?

          SetValue.new(values)
        end

        def evaluate_partial_object_rules(rules)
          hash = partial_object_pairs(rules)
          hash.empty? ? UndefinedValue.new : ObjectValue.new(hash)
        end

        def partial_object_pairs(rules)
          rules.flat_map { |rule| rule_body_values(rule) }.to_h
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

          eval_query(literals, environment).any?
        end

        def evaluate_non_default_rules(rules)
          rules.each do |rule|
            value = evaluate_rule(rule)
            return value unless value.undefined?
          end

          nil
        end

        def query_literal_truthy?(literal)
          eval_query([literal], environment).any?
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
          each_some_solution(literal).any?
        end

        # :reek:TooManyStatements
        def rule_body_values(rule)
          environment.push_scope
          values = Array.new(0, Value.from_ruby(nil))
          eval_rule_body(rule.body, environment).each do |_bindings|
            value = evaluate_rule_value(rule.head)
            values << value unless value.is_a?(UndefinedValue)
          end
          values
        ensure
          environment.pop_scope
        end

        def eval_rule_body(body, env)
          eval_query(Array(body), env)
        end

        # :reek:TooManyStatements
        def eval_query(literals, env)
          literals = Array(literals)
          return Enumerator.new { |yielder| yielder << {} } if literals.empty?

          bound_vars = Environment::RESERVED_NAMES.dup
          context = QueryContext.new(literals: literals, env: env)
          Enumerator.new do |yielder|
            bindings = {} # @type var bindings: Hash[String, Value]
            yield_query_solutions(yielder, context, 0, bindings, bound_vars)
          end
        end

        # rubocop:disable Metrics/MethodLength
        # :reek:TooManyStatements
        # :reek:LongParameterList
        def yield_query_solutions(yielder, context, index, bindings, bound_vars)
          literals = context.literals
          env = context.env
          if index >= literals.length
            yielder << bindings
            return
          end

          literal = literals[index]
          eval_literal(literal, env, bound_vars).each do |literal_bindings|
            merged = merge_bindings(bindings, literal_bindings)
            next unless merged

            env.with_bindings(literal_bindings) do
              next_bound_vars = bound_vars | literal_bindings.keys
              yield_query_solutions(yielder, context, index + 1, merged, next_bound_vars)
            end
          end
        end
        # rubocop:enable Metrics/MethodLength

        def eval_literal(literal, env, bound_vars)
          return eval_query_literal(literal, env, bound_vars) if literal.is_a?(AST::QueryLiteral)
          return eval_some_decl(literal, env) if literal.is_a?(AST::SomeDecl)

          raise EvaluationError.new("Unsupported query literal: #{literal.class}", rule: nil, location: nil)
        end

        def eval_query_literal(literal, env, bound_vars)
          expression = literal.expression
          case expression
          in AST::UnaryOp[operator: :not, operand:]
            eval_not(operand, env, bound_vars)
          else
            expression_evaluator.eval_with_unification(expression, env)
          end
        end

        def eval_not(expr, env, bound_vars)
          check_safety(expr, env, bound_vars)
          Enumerator.new do |yielder|
            solutions = expression_evaluator.eval_with_unification(expr, env)
            yielder << {} unless solutions.any?
          end
        end

        def check_safety(expr, env, bound_vars)
          unbound = unbound_variables(VariableCollector.new.collect(expr), env, bound_vars)
          return if unbound.empty?

          raise_unsafe_negation(expr, unbound)
        end

        def raise_unsafe_negation(expr, unbound)
          message = "Unsafe negation: unbound variables #{unbound.sort.join(", ")}"
          raise EvaluationError.new(message, rule: nil, location: expr.location)
        end

        # :reek:UtilityFunction
        def unbound_variables(names, env, bound_vars)
          safe_names = bound_vars | Environment::RESERVED_NAMES | ["_"]
          names.reject { |name| safe_names.include?(name) || env_bound?(env, name) }.uniq
        end

        # :reek:UtilityFunction
        def env_bound?(env, name)
          !env.lookup(name).is_a?(UndefinedValue)
        end
      end
      # rubocop:enable Metrics/ClassLength
    end
  end
end

require_relative "rule_evaluator/bindings"
