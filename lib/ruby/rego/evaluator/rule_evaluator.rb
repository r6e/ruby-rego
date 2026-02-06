# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Evaluates rule bodies and heads.
      # rubocop:disable Metrics/ClassLength
      # :reek:TooManyMethods
      # :reek:DataClump
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
        # :reek:FeatureEnvy
        def evaluate_rule(rule)
          values = rule_body_values(rule)
          values.empty? ? UndefinedValue.new : values.first
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

          each_body_solution(literals).any?
        end

        def evaluate_non_default_rules(rules)
          rules.each do |rule|
            value = evaluate_rule(rule)
            return value unless value.undefined?
          end

          nil
        end

        def query_literal_truthy?(literal)
          each_literal_solution(literal).any?
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
          each_body_solution(rule.body).each do |_bindings|
            value = evaluate_rule_value(rule.head)
            values << value unless value.is_a?(UndefinedValue)
          end
          values
        ensure
          environment.pop_scope
        end

        def each_body_solution(literals, index = 0, bindings = {})
          Enumerator.new do |yielder|
            yield_body_solutions(yielder, literals, index, bindings)
          end
        end

        # rubocop:disable Metrics/MethodLength
        # :reek:TooManyStatements
        # :reek:LongParameterList
        def yield_body_solutions(yielder, literals, index, bindings)
          if literals.empty? || index >= literals.length
            yielder << bindings
            return
          end

          literal = literals[index]
          each_literal_solution(literal).each do |literal_bindings|
            merged = merge_bindings(bindings, literal_bindings)
            next unless merged

            environment.with_bindings(literal_bindings) do
              yield_body_solutions(yielder, literals, index + 1, merged)
            end
          end
        end
        # rubocop:enable Metrics/MethodLength

        # :reek:NestedIterators
        # :reek:DuplicateMethodCall
        def each_literal_solution(literal)
          Enumerator.new do |yielder|
            case literal
            when AST::QueryLiteral
              expression_evaluator.eval_with_unification(literal.expression, environment).each do |bindings|
                yielder << bindings
              end
            when AST::SomeDecl
              each_some_solution(literal).each { |bindings| yielder << bindings }
            end
          end
        end

        # rubocop:disable Metrics/MethodLength, Metrics/CyclomaticComplexity, Metrics/AbcSize
        # :reek:TooManyStatements
        # :reek:NestedIterators
        # :reek:DuplicateMethodCall
        # :reek:DataClump
        def each_some_solution(literal)
          Enumerator.new do |yielder|
            unless literal.collection
              yielder << {}
              next
            end

            collection_value = expression_evaluator.evaluate(literal.collection)
            next if collection_value.undefined?

            variables = literal.variables
            case collection_value
            when ArrayValue
              each_array_binding(variables, collection_value).each { |bindings| yielder << bindings }
            when SetValue
              each_set_binding(variables, collection_value).each { |bindings| yielder << bindings }
            when ObjectValue
              each_object_binding(variables, collection_value).each { |bindings| yielder << bindings }
            end
          end
        end

        # :reek:TooManyStatements
        # :reek:NestedIterators
        # :reek:FeatureEnvy
        # :reek:DuplicateMethodCall
        # :reek:DataClump
        def each_array_binding(variables, collection_value)
          Enumerator.new do |yielder|
            values = collection_value.to_ruby
            case variables.length
            when 1
              values.each { |value| yielder << bindings_for(variables[0], value) }
            when 2
              values.each_with_index do |value, index|
                bindings = bindings_for(variables[0], index)
                bindings.merge!(bindings_for(variables[1], value))
                yielder << bindings
              end
            end
          end
        end

        # :reek:NestedIterators
        # :reek:FeatureEnvy
        # :reek:DuplicateMethodCall
        # :reek:DataClump
        def each_set_binding(variables, collection_value)
          Enumerator.new do |yielder|
            if variables.length == 1
              collection_value.to_ruby.each do |value|
                yielder << bindings_for(variables[0], value)
              end
            end
          end
        end

        # :reek:TooManyStatements
        # :reek:NestedIterators
        # :reek:FeatureEnvy
        # :reek:DuplicateMethodCall
        # :reek:DataClump
        def each_object_binding(variables, collection_value)
          Enumerator.new do |yielder|
            pairs = collection_value.to_ruby
            case variables.length
            when 1
              pairs.each_key { |key| yielder << bindings_for(variables[0], key) }
            when 2
              pairs.each do |key, value|
                bindings = bindings_for(variables[0], key)
                bindings.merge!(bindings_for(variables[1], value))
                yielder << bindings
              end
            end
          end
        end
        # rubocop:enable Metrics/MethodLength, Metrics/CyclomaticComplexity, Metrics/AbcSize

        # :reek:UtilityFunction
        # :reek:DuplicateMethodCall
        def bindings_for(variable, value)
          return {} if variable.name == "_"

          { variable.name => Value.from_ruby(value) }
        end

        # :reek:UtilityFunction
        # :reek:TooManyStatements
        def merge_bindings(existing, additions)
          merged = existing.dup
          additions.each do |name, value|
            current = merged[name]
            return nil if current && current != value

            merged[name] = value
          end
          merged
        end
      end
      # rubocop:enable Metrics/ClassLength
    end
  end
end
