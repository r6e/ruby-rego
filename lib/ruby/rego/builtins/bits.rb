# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "numeric_helpers"

module Ruby
  module Rego
    module Builtins
      # Built-in bitwise helpers (bits.and/or/xor/negate/lsh/rsh). Operands are
      # integers (integer-valued floats like 12.0 are accepted; non-integers yield an
      # undefined result), and operations use two's-complement infinite precision,
      # matching OPA (Go big.Int).
      module Bits
        extend RegistryHelpers

        BITS_FUNCTIONS = {
          "bits.and" => { arity: 2, handler: :bits_and },
          "bits.or" => { arity: 2, handler: :bits_or },
          "bits.xor" => { arity: 2, handler: :bits_xor },
          "bits.negate" => { arity: 1, handler: :negate },
          "bits.lsh" => { arity: 2, handler: :lsh },
          "bits.rsh" => { arity: 2, handler: :rsh }
        }.freeze

        # Upper bound on a left-shift result's bit length. OPA computes arbitrarily
        # large shifts (slowly), but this pure-Ruby evaluator has no cancellation, so
        # an untrusted policy could otherwise force unbounded allocation. Exceeding the
        # limit yields an undefined result rather than exhausting memory — a deliberate
        # divergence from OPA, affecting only left shifts (the sole growth vector).
        MAX_LSH_RESULT_BITS = 1 << 25

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, BITS_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param left [Ruby::Rego::Value]
        # @param right [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.bits_and(left, right)
          NumberValue.new(integer(left, "bits.and") & integer(right, "bits.and"))
        end

        # @param left [Ruby::Rego::Value]
        # @param right [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.bits_or(left, right)
          NumberValue.new(integer(left, "bits.or") | integer(right, "bits.or"))
        end

        # @param left [Ruby::Rego::Value]
        # @param right [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.bits_xor(left, right)
          NumberValue.new(integer(left, "bits.xor") ^ integer(right, "bits.xor"))
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.negate(value)
          NumberValue.new(~integer(value, "bits.negate"))
        end

        # @param value [Ruby::Rego::Value]
        # @param shift [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.lsh(value, shift)
          base = integer(value, "bits.lsh")
          amount = shift_amount(shift, "bits.lsh")
          ensure_lsh_within_limit(base, amount)
          NumberValue.new(base << amount)
        end

        # @param value [Ruby::Rego::Value]
        # @param shift [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.rsh(value, shift)
          NumberValue.new(integer(value, "bits.rsh") >> shift_amount(shift, "bits.rsh"))
        end

        def self.integer(value, context)
          NumericHelpers.integer_value(value, context: context)
        end
        private_class_method :integer

        # Shift amounts must be non-negative (Go's big.Int Lsh/Rsh take a uint); a
        # negative amount yields an undefined result.
        def self.shift_amount(value, context)
          NumericHelpers.non_negative_integer(value, context: context)
        end
        private_class_method :shift_amount

        # `base.bit_length + amount` upper-bounds the result's magnitude in bits
        # (exact for positive bases; a slight over-estimate for negative bases, which
        # errs toward rejecting — acceptable for a DoS guard). Checked before shifting
        # so an oversized result is never allocated.
        def self.ensure_lsh_within_limit(base, amount)
          return if base.zero?

          result_bits = base.bit_length + amount
          return if result_bits <= MAX_LSH_RESULT_BITS

          raise Ruby::Rego::BuiltinArgumentError.new(
            "bits.lsh result size #{result_bits} bits exceeds maximum #{MAX_LSH_RESULT_BITS}",
            expected: "result <= #{MAX_LSH_RESULT_BITS} bits",
            actual: result_bits,
            context: "bits.lsh",
            location: nil
          )
        end
        private_class_method :ensure_lsh_within_limit
      end
    end
  end
end

Ruby::Rego::Builtins::Bits.register!
