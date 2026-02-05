# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Shared operator application helpers.
      module OperatorEvaluator
        EQUALITY_OPERATORS = {
          eq: ->(lhs, rhs) { BooleanValue.new(lhs == rhs) },
          neq: ->(lhs, rhs) { BooleanValue.new(lhs != rhs) }
        }.freeze
        LOGICAL_OPERATORS = {
          and: ->(lhs, rhs) { BooleanValue.new(lhs.truthy? && rhs.truthy?) },
          or: ->(lhs, rhs) { BooleanValue.new(lhs.truthy? || rhs.truthy?) }
        }.freeze
        COMPARISON_OPERATORS = {
          lt: ->(lhs, rhs) { lhs < rhs },
          lte: ->(lhs, rhs) { lhs <= rhs },
          gt: ->(lhs, rhs) { lhs > rhs },
          gte: ->(lhs, rhs) { lhs >= rhs }
        }.freeze
        ARITHMETIC_OPERATORS = {
          plus: ->(lhs, rhs) { lhs + rhs },
          minus: ->(lhs, rhs) { lhs - rhs },
          mult: ->(lhs, rhs) { lhs * rhs },
          div: ->(lhs, rhs) { lhs / rhs },
          mod: ->(lhs, rhs) { lhs % rhs }
        }.freeze
        UNARY_OPERATORS = {
          not: ->(operand) { BooleanValue.new(!operand.truthy?) },
          minus: lambda do |operand|
            number = numeric_value(operand)
            number ? Value.from_ruby(-number) : UndefinedValue.new
          end
        }.freeze

        # @param operator [Symbol]
        # @param left [Value]
        # @param right [Value]
        # @return [Value]
        def self.apply(operator, left, right)
          apply_logical(operator, left, right) ||
            EQUALITY_OPERATORS[operator]&.call(left, right) ||
            apply_comparison(operator, left, right) ||
            apply_arithmetic(operator, left, right) ||
            UndefinedValue.new
        end

        # @param operator [Symbol]
        # @param operand [Value]
        # @return [Value]
        def self.apply_unary(operator, operand)
          handler = UNARY_OPERATORS[operator]
          return UndefinedValue.new unless handler

          handler.call(operand)
        end

        def self.apply_logical(operator, left, right)
          handler = LOGICAL_OPERATORS[operator]
          handler&.call(left, right)
        end

        def self.apply_comparison(operator, left, right)
          comparison = COMPARISON_OPERATORS[operator]
          return unless comparison

          compare_values(left, right, &comparison)
        end

        def self.apply_arithmetic(operator, left, right)
          arithmetic = ARITHMETIC_OPERATORS[operator]
          return unless arithmetic

          arithmetic_values(operator, left, right, &arithmetic)
        end

        def self.compare_values(left, right)
          left_value = left.to_ruby
          right_value = right.to_ruby
          return UndefinedValue.new unless comparable?(left_value, right_value)

          BooleanValue.new(yield(left_value, right_value))
        rescue ArgumentError
          UndefinedValue.new
        end

        def self.comparable?(left_value, right_value)
          (left_value.is_a?(Numeric) && right_value.is_a?(Numeric)) ||
            (left_value.is_a?(String) && right_value.is_a?(String))
        end

        def self.arithmetic_values(operator, left, right)
          left_value = numeric_value(left)
          right_value = numeric_value(right)
          return UndefinedValue.new unless left_value && right_value
          return UndefinedValue.new if division_by_zero?(operator, right_value)

          Value.from_ruby(yield(left_value, right_value))
        end

        def self.division_by_zero?(operator, right_value)
          %i[div mod].include?(operator) && right_value.zero?
        end

        def self.numeric_value(value)
          ruby = value.to_ruby
          return ruby if ruby.is_a?(Numeric)

          nil
        end
      end
    end
  end
end
