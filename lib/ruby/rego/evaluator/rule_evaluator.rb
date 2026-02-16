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
        # Bundles value evaluation parameters for else/default handling.
        ValueEvaluationContext = Struct.new(:body, :rule, :value_node, :initial_bindings, keyword_init: true)
        # Bundles modifier evaluation state.
        class ModifierContext
          # @param expression [Object]
          # @param env [Environment]
          # @param bound_vars [Array<String>]
          def initialize(expression:, env:, bound_vars:)
            @expression = expression
            @env = env
            @bound_vars = bound_vars
          end

          # @return [Object]
          attr_reader :expression

          # @return [Environment]
          attr_reader :env

          # @return [Array<String>]
          attr_reader :bound_vars

          # @param new_env [Environment]
          # @return [ModifierContext]
          def with_env(new_env)
            self.class.new(expression: expression, env: new_env, bound_vars: bound_vars)
          end
        end

        # @param environment [Environment]
        # @param expression_evaluator [ExpressionEvaluator]
        def initialize(environment:, expression_evaluator:)
          @environment = environment
          @expression_evaluator = expression_evaluator
          @unifier = Unifier.new
        end

        # @param rules [Array<AST::Rule>]
        # @return [Value]
        def evaluate_group(rules)
          return UndefinedValue.new if rules.empty?

          first_rule = rules.first
          return UndefinedValue.new if first_rule.function?
          return evaluate_partial_set_rules(rules) if first_rule.partial_set?
          return evaluate_partial_object_rules(rules) if first_rule.partial_object?

          evaluate_complete_rules(rules)
        end

        # @param name [String]
        # @param args [Array<Value>]
        # @return [Value]
        def evaluate_function_call(name, args)
          cache = memoization&.context&.function_values
          if cache
            key = [name.to_s, args]
            return cache[key] if cache.key?(key)

            cache[key] = evaluate_function_call_uncached(name, args)
            return cache[key]
          end

          evaluate_function_call_uncached(name, args)
        end

        def evaluate_function_call_uncached(name, args)
          rules = environment.rules.fetch(name.to_s) { [] }
          function_rules = rules.select(&:function?)
          return UndefinedValue.new if function_rules.empty?

          value = evaluate_function_rules(function_rules, args)
          return value unless value.is_a?(Array)

          resolved = resolve_conflicts(value, name)
          resolved || UndefinedValue.new
        end

        # @param rule [AST::Rule]
        # @return [Value, Array]
        # :reek:FeatureEnvy
        def evaluate_rule(rule)
          values = rule_body_values(rule)
          resolved = resolve_conflicts(values, rule.name)
          resolved || UndefinedValue.new
        end

        # @param literals [Array<Object>]
        # @param env [Environment]
        # @return [Enumerator]
        # @api private
        def query_solutions(literals, env = environment)
          eval_query(literals, env)
        end

        private

        attr_reader :environment, :expression_evaluator, :unifier

        def memoization
          environment.memoization
        end

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
          pairs = rules.flat_map { |rule| rule_body_pairs(rule) }
          # @type var values: Hash[Object, Value]
          values = {}
          # @type var nested_flags: Hash[Object, bool]
          nested_flags = {}
          pairs.each do |key, value, nested|
            existing = values[key]
            existing_nested = nested_flags[key] || false
            values[key] = merge_partial_object_value(existing, value, key, existing_nested, nested)
            nested_flags[key] = existing_nested || nested
          end
          values
        end

        # :reek:LongParameterList
        def merge_partial_object_value(existing, value, key, existing_nested, current_nested)
          return value unless existing
          return existing if existing == value

          if existing.is_a?(ObjectValue) && value.is_a?(ObjectValue) && existing_nested && current_nested
            merged = merge_object_value_hash(existing.value, value.value, key)
            return ObjectValue.new(merged)
          end

          raise EvaluationError.new("Conflicting object key #{key.inspect}", rule: nil, location: nil)
        end

        def merge_object_value_hash(left, right, key)
          merged = left.dup
          right.each do |child_key, child_value|
            merged[child_key] = merge_object_value_value(merged[child_key], child_value, key)
          end
          merged
        end

        def merge_object_value_value(existing, value, key)
          return value unless existing
          return existing if existing == value

          if existing.is_a?(ObjectValue) && value.is_a?(ObjectValue)
            merged = merge_object_value_hash(existing.value, value.value, key)
            return ObjectValue.new(merged)
          end

          raise EvaluationError.new("Conflicting object key #{key.inspect}", rule: nil, location: nil)
        end

        def evaluate_complete_rules(rules)
          values = rules.reject(&:default_value).map do |rule|
            complete_rule_value_with_else(rule)
          end.reject(&:undefined?)

          resolved = resolve_conflicts(values, rules.first.name)
          return resolved if resolved

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

        def evaluate_complete_rule_value(head, value_node = nil)
          node = value_node || head[:value]
          return expression_evaluator.evaluate(node) if node

          BooleanValue.new(true)
        end

        def body_succeeds?(body)
          literals = Array(body)
          return true if literals.empty?

          eval_query(literals, environment).any?
        end

        def query_literal_truthy?(literal)
          eval_query([literal], environment).any?
        end

        def evaluate_rule_value(head)
          case head[:type]
          when :complete, :function
            evaluate_complete_rule_value(head)
          when :partial_set
            expression_evaluator.evaluate(head[:term])
          else
            UndefinedValue.new
          end
        end

        def some_decl_truthy?(literal)
          each_some_solution(literal).any?
        end

        # :reek:TooManyStatements
        # rubocop:disable Metrics/MethodLength
        def rule_body_values(rule, initial_bindings = {})
          environment.push_scope
          values = environment.with_bindings(initial_bindings) do
            eval_rule_body(rule.body, environment).filter_map do |bindings|
              environment.with_bindings(bindings) do
                value = evaluate_rule_value(rule.head)
                value unless value.is_a?(UndefinedValue)
              end
            end
          end
          values
        ensure
          environment.pop_scope
        end
        # rubocop:enable Metrics/MethodLength

        # :reek:TooManyStatements
        # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
        def rule_body_pairs(rule)
          environment.push_scope
          values = eval_rule_body(rule.body, environment).filter_map do |bindings|
            environment.with_bindings(bindings) do
              pair = evaluate_partial_object_value(rule.head)
              next unless pair.is_a?(Array)

              nested_flag = rule.head.is_a?(Hash) && rule.head[:nested] ? true : false
              [pair[0], pair[1], nested_flag]
            end
          end
          values
        ensure
          environment.pop_scope
        end
        # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

        def complete_rule_value_with_else(rule)
          values = rule_body_values(rule)
          resolved = resolve_conflicts(values, rule.name)
          return resolved if resolved

          else_clause_value(rule, rule.else_clause)
        end

        def else_clause_value(rule, clause)
          return UndefinedValue.new unless clause

          values = evaluate_clause_value(rule, clause, empty_bindings)
          resolved = resolve_conflicts(values, rule.name)
          return resolved if resolved

          else_clause_value(rule, clause[:else_clause])
        end

        def evaluate_value_with_body(context)
          environment.push_scope
          values = values_for_body_context(context)
          values
        ensure
          environment.pop_scope
        end

        def values_for_body_context(context)
          environment.with_bindings(context.initial_bindings) do
            eval_rule_body(context.body, environment).filter_map do |bindings|
              environment.with_bindings(bindings) { evaluate_value_node(context.rule, context.value_node) }
            end
          end
        end

        def evaluate_value_node(rule, value_node)
          value = evaluate_complete_rule_value(rule.head, value_node)
          value unless value.is_a?(UndefinedValue)
        end

        def resolve_conflicts(values, name)
          return nil if values.empty?

          unique = values.uniq
          return unique.first if unique.length == 1

          raise EvaluationError.new("Conflicting values for #{name}", rule: name)
        end

        def evaluate_function_rules(rules, args)
          # @type var values: Array[Value]
          values = []
          rules.reject(&:default_value).each do |rule|
            values.concat(function_rule_values(rule, args))
          end

          return values unless values.empty?

          default_rule = rules.find(&:default_value)
          return [] unless default_rule

          function_rule_values(default_rule, args)
        end

        # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
        def function_rule_values(rule, args)
          head_args = Array(rule.head[:args])
          return [] unless head_args.length == args.length

          # @type var binding_sets: Array[Hash[String, Value]]
          binding_sets = [{}]
          head_args.each_with_index do |pattern, index|
            # @type var next_sets: Array[Hash[String, Value]]
            next_sets = []
            binding_sets.each do |bindings|
              environment.with_bindings(bindings) do
                unifier.unify(pattern, args[index], environment).each do |new_bindings|
                  merged = merge_bindings(bindings, new_bindings)
                  next_sets << merged if merged
                end
              end
            end
            binding_sets = next_sets
          end

          binding_sets.flat_map do |bindings|
            function_values_with_else(rule, bindings)
          end
        end
        # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

        def function_values_with_else(rule, bindings)
          values = rule_body_values(rule, bindings)
          return values unless values.empty?

          function_else_values(rule, rule.else_clause, bindings)
        end

        def function_else_values(rule, clause, bindings)
          return [] unless clause

          values = evaluate_clause_value(rule, clause, bindings)
          return values unless values.empty?

          function_else_values(rule, clause[:else_clause], bindings)
        end

        def empty_bindings
          {} # @type var empty_bindings: Hash[String, Value]
        end

        def evaluate_clause_value(rule, clause, bindings)
          context = ValueEvaluationContext.new(
            body: clause[:body],
            rule: rule,
            value_node: clause[:value],
            initial_bindings: bindings
          )
          evaluate_value_with_body(context)
        end

        def eval_rule_body(body, env)
          eval_query(Array(body), env)
        end

        # :reek:TooManyStatements
        # rubocop:disable Metrics/MethodLength
        def eval_query(literals, env)
          literals = Array(literals)
          if literals.empty?
            # @type var empty_bindings: Hash[String, Value]
            empty_bindings = {}
            return Enumerator.new { |yielder| yielder << empty_bindings }
          end

          Enumerator.new do |yielder|
            with_query_scope(env, literals) do
              bound_vars = Environment::RESERVED_NAMES.dup
              context = QueryContext.new(literals: literals, env: env)
              # @type var bindings: Hash[String, Value]
              bindings = {}
              yield_query_solutions(yielder, context, 0, bindings, bound_vars)
            end
          end
        end
        # rubocop:enable Metrics/MethodLength

        def with_query_scope(env, literals)
          env.push_scope
          shadow_query_locals(env, literals)
          yield
        ensure
          env.pop_scope
        end

        def shadow_query_locals(env, literals)
          details = BoundVariableCollector.new.collect_details(literals)
          explicit = details[:explicit]
          shadow_explicit_locals(env, explicit)
          shadow_unification_locals(env, details[:unification], explicit)
        end

        def shadow_explicit_locals(env, names)
          names.each { |name| bind_undefined(env, name) }
        end

        def shadow_unification_locals(env, names, explicit_names)
          names.each do |name|
            next if explicit_names.include?(name)
            next unless env.lookup(name).is_a?(UndefinedValue)

            bind_undefined(env, name)
          end
        end

        # :reek:UtilityFunction
        def bind_undefined(env, name)
          return if Environment::RESERVED_NAMES.include?(name) || name == "_"

          env.bind(name, UndefinedValue.new)
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
          modifiers = literal.with_modifiers
          return eval_query_expression(expression, env, bound_vars) if modifiers.empty?

          context = ModifierContext.new(expression: expression, env: env, bound_vars: bound_vars)
          with_modifiers_enum(modifiers, context)
        end

        # :reek:NestedIterators
        def with_modifiers_enum(modifiers, context)
          Enumerator.new do |yielder|
            WithModifiers::WithModifierApplier.apply(modifiers, context.env, expression_evaluator) do |modified_env|
              yield_query_expression(yielder, context.with_env(modified_env))
            end
          end
        end

        # :reek:FeatureEnvy
        def yield_query_expression(yielder, context)
          eval_query_expression(context.expression, context.env, context.bound_vars).each do |bindings|
            yielder << bindings
          end
        end

        def eval_query_expression(expression, env, bound_vars)
          case expression
          in AST::UnaryOp[operator: :not, operand:]
            eval_not(operand, env, bound_vars)
          else
            expression_evaluator.eval_with_unification(expression, env)
          end
        end

        def eval_not(expr, env, bound_vars)
          if expr.is_a?(AST::Every)
            raise EvaluationError.new("Negating every is not supported", rule: nil, location: expr.location)
          end

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
