# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Query evaluation for rule bodies: scoping, local shadowing, literal and
      # expression dispatch, with-modifier application, and negation safety.
      # rubocop:disable Metrics/ClassLength
      # :reek:DataClump
      class RuleEvaluator
        private

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

        # These shadow helpers thread an explicit +env+ (mirroring +with_query_scope+, which
        # pushes/pops scope on the same parameter) rather than closing over +environment+.
        # That is deliberate: Evaluator::LocalShadowing is the instance-+environment+ variant
        # used by ExpressionEvaluator/ComprehensionEvaluator; unifying the two would require
        # de-parameterizing the whole query cluster, not a mixin include.
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
          results = [] # @type var results: Array[Hash[String, Value]]
          WithModifiers::WithModifierApplier.apply(modifiers, context.env, expression_evaluator) do |modified_env|
            eval_query_expression(context.expression, modified_env, context.bound_vars).each do |bindings|
              results << bindings
            end
          end

          Enumerator.new do |yielder|
            results.each { |bindings| yielder << bindings }
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
