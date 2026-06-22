# frozen_string_literal: true

require "flt"
require "bigdecimal"
require_relative "go_number_format"

module Ruby
  module Rego
    # An OPA-faithful arbitrary-precision number.
    #
    # OPA stores a Rego number as a json.Number — the original decimal TEXT, preserved verbatim
    # (`1.50` stays `1.50`, `1e999` stays `1e999`) — and does arithmetic in Go's math/big.Float at
    # 64-bit binary precision with round-half-even, formatting the result with Go's FloatToNumber rules.
    # Ruby's Float (IEEE-754 double) cannot match that: it loses precision past 2^53 and overflows to
    # Float::INFINITY, which then crashes JSON serialization. This class reproduces OPA exactly:
    #
    #   * a LITERAL carries its source text and serializes it back verbatim (#to_s / #to_json);
    #   * arithmetic runs through Flt::BinNum (precision 64, half-even — the math/big.Float equivalent),
    #     fed exact rationals so the rounding matches Go's big.Float.SetString, and the result is
    #     formatted with Go's strconv 'g' / 'f' conventions ({GoNumberFormat});
    #   * equality and ordering use an exact Rational (#exact), so `1.50 == 1.5` and `1.0 == 1`.
    #
    # Integers stay Ruby Integer (already arbitrary-precision); only non-integers are Number. An
    # arithmetic result that is integer-valued collapses back to a Ruby Integer, matching OPA
    # (`1.0 + 1.0` -> `2`, `1e308 * 1e308` -> the full ~600-digit integer).
    #
    # rubocop:disable Metrics/ClassLength -- a cohesive Numeric value object: the full Numeric protocol
    # (conversions, ordering, coercion, the four operators) plus the OPA div/mod helpers and the flt
    # arithmetic backend belong together; splitting them would only scatter the contract.
    class Number < Numeric
      # Go's math/big.Float number context: 64-bit binary precision, round-half-even, and an exponent
      # range wide enough for any decimal literal OPA accepts (well beyond 1e±999).
      CONTEXT = Flt::BinNum::Context(precision: 64, rounding: :half_even, emax: 2**30, emin: -(2**30))

      # Build a Number from a numeric literal's source text (already validated by the lexer).
      #
      # @param text [String]
      # @return [Number]
      def self.literal(text)
        new(text: text)
      end

      # Format a computed Flt::BinNum result the way OPA's FloatToNumber does, working from the result's
      # SHORTEST round-tripping digits (not its exact binary value): an integer-valued result renders as
      # Go's 'f' verb — full decimal, no exponent — and collapses to a Ruby Integer (so `1.0 + 1.0` is
      # `2` and `1e308 * 1e308` is `9999999999999999999` followed by zeros, matching OPA, not the exact
      # binary `...9114207...`); a fractional result becomes a Number carrying its Go 'g'-formatted text.
      #
      # @param binnum [Flt::BinNum]
      # @return [Number, Integer]
      def self.from_binnum(binnum)
        # Pad the coefficient to the full 64-bit precision so flt's shortest format computes its
        # round-trip tolerance at 64 bits. An EXACT result (e.g. 1 - 0.25 -> 0.75, stored in 2 bits)
        # would otherwise be reported within its own narrow precision and mis-shorten (0.75 -> "0.8").
        binnum = CONTEXT.normalize(binnum) unless binnum.zero?
        digits, point = GoNumberFormat.shortest_digits(binnum.to_s(all_digits: false))
        negative = binnum.sign.negative?
        if binnum.integral?
          magnitude = GoNumberFormat.fixed(digits, point).to_i
          negative ? -magnitude : magnitude
        else
          new(text: GoNumberFormat.render(digits, point, negative))
        end
      end

      # Wrap any Ruby Numeric as a Number for use as an arithmetic operand.
      #
      # @param value [Numeric]
      # @return [Number]
      def self.from_numeric(value)
        return value if value.is_a?(Number)
        return new(exact: value) if value.is_a?(Integer) || value.is_a?(Rational)

        new(exact: BigDecimal(value.to_s).to_r) # Float: via its shortest decimal, matching #exact
      end

      # Rego division is always big.Float (OPA `5 / 2` -> 2.5); an integer-valued quotient collapses to
      # an Integer (`4 / 2` -> 2). The caller guards a zero divisor to undefined.
      #
      # @param left [Numeric]
      # @param right [Numeric]
      # @return [Number, Integer]
      def self.div(left, right)
        from_numeric(left) / right
      end

      # Rego modulo is integer-only and undefined otherwise: both operands must be integer-VALUED (so
      # `4.0 % 2` -> 0 but `5.5 % 2` is undefined), and the result is Go's truncated remainder, taking
      # the sign of the dividend (`-5 % 3` -> -2). Returns nil when an operand is not integer-valued, so
      # the caller maps it to undefined. The caller guards a zero divisor.
      #
      # @param left [Numeric]
      # @param right [Numeric]
      # @return [Integer, nil]
      def self.modulo(left, right)
        dividend = integer_value(left)
        divisor = integer_value(right)
        return nil unless dividend && divisor

        dividend.remainder(divisor)
      end

      # The exact Integer value of an integer-valued operand, or nil when it is not integer-valued.
      #
      # @param value [Numeric]
      # @return [Integer, nil]
      def self.integer_value(value)
        case value
        when Integer then value
        when Number then value.integer_valued? ? value.to_i : nil
        when Float then float_integer_value(value)
        end
      end

      # @return [Integer, nil]
      def self.float_integer_value(value)
        return nil unless value.finite?

        truncated = value.to_i
        value == truncated ? truncated : nil
      end
      private_class_method :float_integer_value

      # @param text [String, nil] canonical decimal text (authoritative for a literal)
      # @param exact [Rational, Integer, nil] exact value (authoritative for an operand wrap)
      def initialize(text: nil, exact: nil)
        super()
        @text = text&.freeze
        @exact = normalize_exact(exact)
      end

      # The canonical decimal text. For a literal this is the verbatim source; for a computed result the
      # Go-formatted shortest text; for an operand wrap it is derived from the exact value on demand.
      #
      # @return [String]
      def to_s
        @text ||= self.class.from_binnum(to_binnum).to_s # rubocop:disable Naming/MemoizedInstanceVariableName
      end

      alias inspect to_s

      # Emit as a raw JSON number token (valid JSON: the canonical decimal text). JSON.generate
      # dispatches here for a custom Numeric, so a Number serializes with full fidelity and never as a
      # non-finite token.
      #
      # @return [String]
      def to_json(*_args)
        to_s
      end

      # Exact value for equality / ordering / canonicalization: a Rational, or an Integer when the value
      # is integer-valued.
      #
      # @return [Rational, Integer]
      def exact
        @exact ||= normalize_exact(BigDecimal(to_s).to_r)
      end

      # @return [Boolean]
      def integer_valued?
        exact.is_a?(Integer)
      end

      # @return [Boolean]
      def zero?
        exact.zero?
      end

      # @return [Boolean]
      def negative?
        exact.negative?
      end

      # @return [Float] lossy, like Go's float64 conversion (may be ±Infinity for huge magnitudes)
      def to_f
        to_s.to_f
      end

      # @return [Integer] truncated toward zero
      def to_i
        exact.to_i
      end
      alias to_int to_i

      # @return [Rational]
      def to_r
        exact.to_r
      end

      # round / ceil / floor / truncate / abs operate on the EXACT value, never `to_f`, so a
      # magnitude beyond Float range (e.g. `round(1e400)`) yields its exact integer instead of raising
      # FloatDomainError (Ruby's Numeric#round routes through to_f, which would overflow to Infinity and
      # crash). Rounding is half-away-from-zero, matching OPA. (For magnitudes beyond Float precision the
      # exact integer differs in its low-order digits from OPA's big.Float rounding — a fidelity detail
      # deferred to the builtin number sweep; normal-magnitude values match OPA byte-for-byte.)
      #
      # @return [Integer]
      def round(_ndigits = 0)
        exact.round
      end

      # @return [Integer]
      def ceil(_ndigits = 0)
        exact.ceil
      end

      # @return [Integer]
      def floor(_ndigits = 0)
        exact.floor
      end

      # @return [Integer]
      def truncate(_ndigits = 0)
        exact.to_i
      end

      # @return [Number, Integer] Integer when the magnitude is integer-valued, else a Number
      def abs
        magnitude = exact.abs
        magnitude.is_a?(Integer) ? magnitude : self.class.from_numeric(magnitude)
      end

      # Order against any Numeric by exact value (so 1.50 <=> 1.5 is 0 and 1.0 <=> 1 is 0).
      #
      # @param other [Object]
      # @return [Integer, nil]
      def <=>(other)
        rational = rational_of(other)
        return nil unless rational

        exact <=> rational
      end

      # Let `Integer <op> Number` / `Float <op> Number` route through Number's flt arithmetic and
      # exact-value ordering, preserving operand order for the non-commutative operators.
      #
      # @param other [Numeric]
      # @return [Array(Number, Number)]
      def coerce(other)
        [self.class.from_numeric(other), self]
      end

      # @return [Number]
      def -@
        self.class.from_numeric(-exact)
      end

      def +(other)
        arithmetic(:add, other)
      end

      def -(other)
        arithmetic(:subtract, other)
      end

      def *(other)
        arithmetic(:multiply, other)
      end

      def /(other)
        arithmetic(:divide, other)
      end

      # @return [Integer]
      def hash
        exact.hash
      end

      # @return [Boolean]
      def eql?(other)
        other.is_a?(Number) && exact == other.exact
      end

      # Round an exact rational to the prec-64 binary float context, mirroring Go's big.Float.SetString:
      # numerator and denominator are each exact in the context, then divided, so the rounding lands on
      # the same float OPA would compute for that literal.
      #
      # @param rational [Rational, Integer]
      # @return [Flt::BinNum]
      def self.rational_to_binnum(rational)
        rational = rational.to_r
        CONTEXT.divide(CONTEXT.Num(rational.numerator), CONTEXT.Num(rational.denominator))
      end

      protected

      # @return [Flt::BinNum]
      def to_binnum
        self.class.rational_to_binnum(exact)
      end

      private

      # @return [Number, Integer]
      def arithmetic(operation, other)
        klass = self.class
        rational = rational_of(other)
        raise ::TypeError, "#{other.class} can't be coerced into #{klass}" unless rational

        klass.from_binnum(CONTEXT.send(operation, to_binnum, klass.rational_to_binnum(rational)))
      end

      # Exact rational of any Numeric operand, or nil if it is not numeric.
      #
      # @return [Rational, nil]
      def rational_of(other)
        case other
        when Number then other.exact.to_r
        when Integer, Rational then other.to_r
        when Float then BigDecimal(other.to_s).to_r
        end
      end

      # Reduce an integer-valued Rational to an Integer so #exact / canonicalization unify `1.0` and `1`.
      #
      # @return [Rational, Integer, nil]
      def normalize_exact(value)
        return value unless value.is_a?(Rational)

        value.denominator == 1 ? value.numerator : value
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
end
