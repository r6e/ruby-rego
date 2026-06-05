# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Partial set/object rule evaluation and object-value merging.
      class RuleEvaluator
        private

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
      end
    end
  end
end
