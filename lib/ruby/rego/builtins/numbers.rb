# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "numeric_helpers"

module Ruby
  module Rego
    module Builtins
      # Built-in numeric helpers (abs, round, ceil, floor, numbers.range,
      # numbers.range_step).
      # rubocop:disable Metrics/ModuleLength
      module Numbers
        extend RegistryHelpers

        NUMBER_FUNCTIONS = {
          "abs" => { arity: 1, handler: :abs },
          "round" => { arity: 1, handler: :round },
          "ceil" => { arity: 1, handler: :ceil },
          "floor" => { arity: 1, handler: :floor },
          "numbers.range" => { arity: 2, handler: :range },
          "numbers.range_step" => { arity: 3, handler: :range_step }
        }.freeze

        # Upper bound on `numbers.range` length. OPA halts large ranges via context
        # cancellation; this pure-Ruby evaluator has no such escape valve, so an
        # untrusted policy could otherwise force unbounded allocation. Exceeding the
        # limit yields an undefined result rather than exhausting memory.
        MAX_RANGE_SIZE = 1_000_000

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, NUMBER_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.abs(value)
          NumberValue.new(normalize(numeric(value, "abs").abs))
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.round(value)
          NumberValue.new(numeric(value, "round").round)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.ceil(value)
          NumberValue.new(numeric(value, "ceil").ceil)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.floor(value)
          NumberValue.new(numeric(value, "floor").floor)
        end

        # Inclusive integer range, ascending or descending.
        #
        # Matches OPA: integer-valued floats (e.g. 3.0) are accepted as bounds,
        # while a non-integer bound (e.g. 1.5) yields an undefined result.
        #
        # @param start_value [Ruby::Rego::Value]
        # @param end_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        def self.range(start_value, end_value)
          start_bound = NumericHelpers.integer_value(start_value, context: "numbers.range")
          end_bound = NumericHelpers.integer_value(end_value, context: "numbers.range")
          ensure_range_within_limit(start_bound, end_bound)

          ArrayValue.new(range_elements(start_bound, end_bound).map { |number| NumberValue.new(number) })
        end

        # numbers.range_step(low, high, step): like numbers.range but advancing by a
        # positive integer step; the endpoint is included only when it lands exactly
        # on a step. A non-positive or non-integer step yields undefined (matching OPA).
        #
        # @param start_value [Ruby::Rego::Value]
        # @param end_value [Ruby::Rego::Value]
        # @param step_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        # :reek:TooManyStatements
        def self.range_step(start_value, end_value, step_value)
          start_bound = NumericHelpers.integer_value(start_value, context: "numbers.range_step")
          end_bound = NumericHelpers.integer_value(end_value, context: "numbers.range_step")
          step = NumericHelpers.integer_value(step_value, context: "numbers.range_step")
          ensure_positive_step(step)
          ensure_step_range_within_limit(start_bound, end_bound, step)

          elements = step_elements(start_bound, end_bound, step)
          ArrayValue.new(elements.map { |number| NumberValue.new(number) })
        end

        # Extracts a finite numeric value, rejecting non-finite floats (Infinity,
        # NaN) so that round/ceil/floor never raise FloatDomainError and abs never
        # produces an unrepresentable result.
        #
        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [Numeric]
        def self.numeric(value, context)
          Base.assert_type(value, expected: NumberValue, context: context)
          number = value.value
          return number unless number.is_a?(Float) && !number.finite?

          raise Ruby::Rego::BuiltinArgumentError.new(
            "Expected a finite number",
            expected: "finite number",
            actual: number,
            context: context,
            location: nil
          )
        end
        private_class_method :numeric

        # Normalizes an integer-valued float to an Integer, matching OPA's numeric
        # output (e.g. abs(-2.0) => 2, not 2.0). Non-integer floats are preserved.
        #
        # @param number [Numeric]
        # @return [Numeric]
        def self.normalize(number)
          return number.to_i if number.is_a?(Float) && number.modulo(1).zero?

          number
        end
        private_class_method :normalize

        # @param start_bound [Integer]
        # @param end_bound [Integer]
        # @return [void]
        def self.ensure_range_within_limit(start_bound, end_bound)
          size = (end_bound - start_bound).abs + 1
          return if size <= MAX_RANGE_SIZE

          raise Ruby::Rego::BuiltinArgumentError.new(
            "numbers.range size #{size} exceeds maximum #{MAX_RANGE_SIZE}",
            expected: "size <= #{MAX_RANGE_SIZE}",
            actual: size,
            context: "numbers.range",
            location: nil
          )
        end
        private_class_method :ensure_range_within_limit

        # @param start_bound [Integer]
        # @param end_bound [Integer]
        # @return [Array<Integer>]
        def self.range_elements(start_bound, end_bound)
          return (start_bound..end_bound).to_a if start_bound <= end_bound

          start_bound.downto(end_bound).to_a
        end
        private_class_method :range_elements

        # @param step [Integer]
        # @return [void]
        def self.ensure_positive_step(step)
          return if step.positive?

          raise Ruby::Rego::BuiltinArgumentError.new(
            "numbers.range_step step must be positive",
            expected: "step >= 1",
            actual: step,
            context: "numbers.range_step",
            location: nil
          )
        end
        private_class_method :ensure_positive_step

        # @param start_bound [Integer]
        # @param end_bound [Integer]
        # @param step [Integer]
        # @return [void]
        def self.ensure_step_range_within_limit(start_bound, end_bound, step)
          size = ((end_bound - start_bound).abs / step) + 1
          return if size <= MAX_RANGE_SIZE

          raise Ruby::Rego::BuiltinArgumentError.new(
            "numbers.range_step size #{size} exceeds maximum #{MAX_RANGE_SIZE}",
            expected: "size <= #{MAX_RANGE_SIZE}",
            actual: size,
            context: "numbers.range_step",
            location: nil
          )
        end
        private_class_method :ensure_step_range_within_limit

        # @param start_bound [Integer]
        # @param end_bound [Integer]
        # @param step [Integer]
        # @return [Array<Integer>]
        def self.step_elements(start_bound, end_bound, step)
          direction = start_bound <= end_bound ? step : -step
          start_bound.step(end_bound, direction).to_a
        end
        private_class_method :step_elements
      end
      # rubocop:enable Metrics/ModuleLength
    end
  end
end

Ruby::Rego::Builtins::Numbers.register!
