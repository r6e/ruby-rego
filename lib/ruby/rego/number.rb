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
      # The big.Float engine's binary-exponent ceiling (and, negated, its floor): wide enough for any
      # decimal literal OPA accepts (well beyond 1e±999). Exposed as a named constant — rather than
      # buried in CONTEXT — so the units DoS-safety invariant test can assert against it without reaching
      # into the CONTEXT object, keeping a single source of truth if the range is ever retuned.
      ENGINE_EMAX = 2**30

      # Go's math/big.Float number context: 64-bit binary precision, round-half-even, and the ENGINE_EMAX
      # exponent range.
      CONTEXT = Flt::BinNum::Context(precision: 64, rounding: :half_even, emax: ENGINE_EMAX, emin: -ENGINE_EMAX)

      # The largest decimal order of magnitude OPA accepts in a numeric literal: a literal whose
      # magnitude exceeds 10**30102 (or whose reciprocal does) is a parse error in OPA ("number too
      # big"). It is also the guard against a denial of service — `BigDecimal(text).to_r` materializes a
      # numerator or denominator of ~10**|magnitude| as a full Integer, so an unbounded exponent (e.g.
      # `1e999999999`, 11 source bytes -> a gigabyte rational) would otherwise exhaust memory.
      #
      # The cap matches OPA across the entire realistic range. Two known edges, both bounded and far
      # beyond any real policy value (documented, not a DoS): (1) OPA's bound is very slightly asymmetric
      # (the tiny-magnitude side reaches ~10**-30150); this symmetric cap is marginally stricter there.
      # (2) At the extreme large edge the gem and OPA can differ by one order of magnitude: this gate uses
      # BigDecimal's EXACT magnitude, whereas OPA rounds the literal to a big.Float at its precision first,
      # so a value just below 10**30103 (e.g. a 30103-digit all-nines integer) rounds UP across OPA's
      # boundary and is rejected by OPA but accepted here. Verified vs opa eval 1.17. Matching OPA's
      # rounding-at-the-boundary behaviour would require porting its big.Float parser — a tracked follow-up
      # in the number-model fidelity sweep, not this scope. Pre-existing; unaffected by the gate refactor.
      MAX_MAGNITUDE_EXPONENT = 30_102

      # log10(2), for estimating a BinNum's base-10 order of magnitude from its binary exponent without
      # materializing the value. Used only by {magnitude_exceeds_cap?} (the `product` DoS gate).
      LOG10_2 = Math.log10(2)

      # Build a Number from a numeric literal's source text (already validated by the lexer).
      #
      # @param text [String]
      # @return [Number]
      def self.literal(text)
        new(text: text)
      end

      # OPA's strict JSON-number grammar, UNanchored: an optional leading `-`, no leading zeros (`0` or
      # `[1-9]\d*`), an optional `.` fraction, an optional `e`/`E` exponent. The single authoritative
      # source; the JSON decoder derives its scannable `JsonDecoder::NUMBER` from this and `DECIMAL_STRING`
      # anchors it, so the grammar can never silently drift between the three sites.
      NUMBER_CORE = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/

      # `NUMBER_CORE` anchored to a whole string. Used by `to_number` to validate a full string the way the
      # lexer/decoder validate a token (rejects `007`, `1.`, `.5`, `+5`, surrounding whitespace, hex,
      # `NaN`/`Infinity`).
      DECIMAL_STRING = /\A#{NUMBER_CORE.source}\z/

      # A number token is a fractional/exponent form iff it carries `.`/`e`/`E`. The single predicate the
      # decoder, `build_number`, and `magnitude_within_limit?` share for their literal-vs-Integer dispatch.
      FRACTIONAL = /[.eE]/

      # Build a parsed value from already-grammar-validated number text: a fractional/exponent form — or
      # `-0`, whose canonical Integer form `0` would drop OPA's verbatim sign — becomes a text-preserving
      # Number; a plain integer becomes an exact Integer. `fractional` is a dispatch hint: the JSON decoder
      # threads its precomputed flag through; `to_number` passes nothing and lets the default re-derive it
      # (it has already scanned the bounded-magnitude text, so the extra O(n) scan is immaterial there). It
      # carries NO validation — the caller MUST have already gated the text's grammar, encoding, and
      # magnitude, because this materializes the value.
      #
      # @param text [String]
      # @param fractional [bool] whether `text` has `.`/`e`/`E`
      # @return [Number, Integer]
      # :reek:ControlParameter -- `fractional` is a precomputed dispatch flag selecting the literal vs
      # Integer branch, passed to skip a second O(n) scan of a large token; the default re-derives it.
      def self.build_number(text, fractional: text.match?(FRACTIONAL))
        fractional || text == "-0" ? literal(text) : Integer(text, 10)
      end

      # Whether `text`'s decimal order of magnitude is within OPA's literal limit. The single magnitude
      # gate all three callers (the lexer, the JSON decoder, and `to_number`) share. A fractional/exponent
      # form reads its magnitude
      # from BigDecimal's exponent (which records the position of the decimal point WITHOUT materializing
      # 10**exponent), so this is O(text length) and safe on attacker-controlled input — unlike the `to_r`
      # that #exact would later perform; a plain integer is checked by digit count alone. The lexer calls
      # this to reject an over-large literal as a parse error, very nearly as OPA does (the bound is exact
      # across the entire realistic range; at the extreme edge it can differ by one order of magnitude —
      # see MAX_MAGNITUDE_EXPONENT).
      #
      # An exponent literal of ~19+ digits silently saturates BigDecimal at construction (it does NOT
      # raise): a huge POSITIVE exponent (`1e9999999999999999999`) becomes Infinity, and a huge NEGATIVE
      # one (`1e-9999999999999999999`) underflows to 0 — both with exponent 0, which would slip past the
      # magnitude check. An accepted-but-saturated number then crashes (Infinity -> FloatDomainError on
      # the later #exact) or silently mis-evaluates as 0. The finite? guard rejects the positive case;
      # the zero_literal? check distinguishes a genuine zero from an underflowed tiny non-zero, rejecting
      # the latter. Both directions thus map to a parse/argument error, consistent with the cap and safer
      # than OPA (which stores such a number as text and then panics on comparison).
      #
      # @param text [String]
      # @param fractional [bool] whether `text` is a fractional/exponent form (has `.`/`e`/`E`). The JSON
      #   decoder and the lexer each precompute this for their literal-vs-Integer dispatch and thread it
      #   here to avoid a second full-string scan on an attacker-controlled megabyte token; only `to_number`
      #   passes nothing and the default re-derives it.
      # @return [Boolean]
      # :reek:ControlParameter -- `fractional` is a precomputed dispatch flag the callers pass to skip a
      # second O(n) scan of a huge token; it legitimately selects the integer vs decimal magnitude path.
      def self.magnitude_within_limit?(text, fractional: text.match?(FRACTIONAL))
        return integer_magnitude_within_limit?(text) unless fractional

        decimal = BigDecimal(text)
        return false unless decimal.finite?
        return zero_literal?(text) if decimal.zero?

        (decimal.exponent - 1).abs <= MAX_MAGNITUDE_EXPONENT
      end

      # A plain integer's magnitude is its significant-digit count minus one. The NUMBER grammar (both
      # the lexer and the JSON decoder) forbids leading zeros, so the digit count is exact — an O(1) check
      # (the sign is subtracted from the length, NOT stripped into a copy, so a megabyte integer token
      # costs O(1) here). Verified equivalent to the BigDecimal exponent path across sign and zero forms.
      #
      # @param text [String]
      # @return [Boolean]
      def self.integer_magnitude_within_limit?(text)
        digits = text.length
        digits -= 1 if text.start_with?("-")
        digits <= MAX_MAGNITUDE_EXPONENT + 1
      end
      private_class_method :integer_magnitude_within_limit?

      # Whether `text` denotes an exact zero (every significant digit is 0, e.g. "0", "-0", "0.0",
      # "0e1000"), as opposed to a tiny non-zero whose huge negative exponent underflowed BigDecimal to 0.
      #
      # @param text [String]
      # @return [Boolean]
      def self.zero_literal?(text)
        text.sub(/[eE].*/, "").delete("-+.").match?(/\A0+\z/)
      end

      # Format a computed Flt::BinNum result the way OPA's FloatToNumber does, working from the result's
      # SHORTEST round-tripping digits (not its exact binary value): an integer-valued result renders as
      # Go's 'f' verb — full decimal, no exponent — and collapses to a Ruby Integer (so `1.0 + 1.0` is
      # `2` and `1e308 * 1e308` is `9999999999999999999` followed by zeros, matching OPA, not the exact
      # binary `...9114207...`); a fractional result becomes a Number carrying its Go 'g'-formatted text.
      #
      # OPA's big.Float keeps IEEE signed zero (so `product([0, -2])` and `0 / -1` format as "-0"), but
      # this exact-Rational model collapses every zero to the unsigned Integer 0 (and `BigDecimal("-0.0").to_r`
      # is already 0). Signed zero — across literals, operands, and computed results alike — is one
      # tracked number-model gap, deferred to the dedicated number sweep rather than half-fixed here.
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

      # Negate a numeric literal value while PRESERVING its text (so `-1.50` keeps `-1.50`, not `-1.5`):
      # a Number toggles the sign of its text; a plain Integer negates normally. Used by the parser when
      # folding a unary minus directly onto a literal.
      #
      # @param value [Number, Integer]
      # @return [Number, Integer]
      def self.negate_literal(value)
        return -value unless value.is_a?(Number)

        text = value.to_s
        literal(text.start_with?("-") ? text.delete_prefix("-") : "-#{text}")
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

      # round / ceil / floor / truncate operate on the PRECISION-64 binary value (#to_binnum), exactly as
      # OPA's round/ceil/floor do (they convert the json.Number to a big.Float at precision 64 and round
      # that), so a value within half an ulp of a half-integer rounds as OPA does (`round(0.4999…9)` ->
      # 1) and `round(1e400)` yields the big.Float-rounded integer byte-for-byte. They never route
      # through `to_f` (which would overflow to Infinity and raise FloatDomainError). Rounding is
      # half-away-from-zero, matching OPA.
      #
      # @return [Integer]
      def round(_ndigits = 0)
        binary_value.round
      end

      # @return [Integer]
      def ceil(_ndigits = 0)
        binary_value.ceil
      end

      # @return [Integer]
      def floor(_ndigits = 0)
        binary_value.floor
      end

      # @return [Integer]
      def truncate(_ndigits = 0)
        binary_value.to_i
      end

      # abs preserves the EXACT value (OPA's abs keeps the json.Number: abs(-1e400) is the clean 10**400,
      # not a big.Float-rounded value), unlike round/ceil/floor.
      #
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

      # Negate, keeping the result a Number (it serializes to the same canonical text as the equivalent
      # Integer — `-(1.0)` -> `-1` — and equality unifies them). Deliberately NOT collapsed to a Ruby
      # Integer: a huge integer-valued magnitude must stay a Number so yaml.marshal renders it through the
      # OPA-faithful float64 path (`-1e308` -> `-1e+308`); a Ruby Integer would render full digits, which
      # is the pre-existing yaml-vs-OPA gap for large integers (tracked for the yaml/number sweep).
      #
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

      # Multiply an exact `rational` by an exact `integer` in the precision-64 big.Float context and
      # truncate the product toward zero — reproducing OPA's units.parse_bytes arithmetic byte-for-byte
      # (Go math/big: big.Float.SetString → Mul → Int). `rational_to_binnum` rounds the rational to the
      # float big.Float.SetString would yield, `CONTEXT.multiply` rounds the product again at 64 bits
      # like Mul, and `to_i` truncates toward zero like Int (so a negative is NOT floored). The integer
      # multiplier must be a uint64 (0..2**64-1), matching OPA's m.SetUint64: every uint64 is exact at
      # precision 64, so CONTEXT.Num never rounds it (OPA's unit multipliers are all <= 2**60). Encapsulates
      # the Flt engine so callers never touch CONTEXT directly. The caller must bound the operands so the
      # product stays finite (see the units guards).
      #
      # @param rational [Rational]
      # @param integer [Integer]
      # @return [Integer]
      def self.prec64_multiply_truncate(rational, integer)
        # Fail fast on an out-of-contract multiplier rather than let CONTEXT.Num silently round it to a
        # different value (a wrong result). The contract is uint64 (OPA's SetUint64 domain), not a
        # bit_length test — every uint64 is exact at prec 64, and this also rejects negatives. OPA's unit
        # multipliers are all <= 2**60, so this never fires in practice; it protects a future/incorrect caller.
        unless integer.between?(0, (2**64) - 1)
          raise ArgumentError, "multiplier #{integer} is outside the uint64 range (OPA multiplies via SetUint64)"
        end

        CONTEXT.multiply(rational_to_binnum(rational), CONTEXT.Num(integer)).to_i
      end

      # Multiply every element of `numbers` in the precision-64 big.Float context, reproducing OPA's
      # `product` aggregate byte-for-byte. OPA seeds a big.Float at 1 and folds each element through
      # Mul at precision 64; it has NO integer fast-path (unlike `sum`), so an all-integer product is
      # the prec-64-ROUNDED value, not the exact integer (`[2**32, 2**32, 2**32]` -> the big.Float
      # rounding of 2**96, which FloatToNumber renders shortest, NOT 79228162514264337593543950336).
      # The accumulator therefore stays a BinNum across the whole fold: collapsing an integer-valued
      # intermediate back to Integer (as the `*` operator does) would resume EXACT native integer
      # multiplication and diverge from OPA. Each element is taken as its exact value first (a raw
      # Float via its shortest decimal, like the literal OPA parsed), then rounded to the prec-64
      # float OPA's NumberToFloat yields. An empty `numbers` returns the seed, formatting to Integer 1.
      #
      # Large-magnitude integer-valued products inherit the number model's shortest-form limitation
      # shared with `div`: flt's shortest decimal can differ from Go strconv's by one digit at the
      # extreme (`[2**32]*3` -> ...594 here vs OPA's ...590). Pre-existing, tracked in the number sweep.
      #
      # DoS: `product` is the one numeric builtin with an UNBOUNDED fold (N comprehension-controlled
      # elements, each near the literal cap), so it is the only one whose result magnitude can grow
      # without bound from small input — N near-cap factors give an N x cap result. A single op like
      # `*` or `/` is bounded by ~2x the cap, so those are deliberately left uncapped to MATCH OPA
      # (`1e308 * 1e308` -> the full ~600-digit integer, as the number model intends); this cap does NOT
      # claim a global magnitude invariant. Two gates keep `product` total: the engine's Overflow trap
      # stops an intermediate beyond ENGINE_EMAX (a ~10**9-digit integer) mid-fold, and
      # {magnitude_exceeds_cap?} rejects a FINAL result past MAX_MAGNITUDE_EXPONENT before {from_binnum}
      # would materialize it as a multi-megabyte Integer string. Both map to undefined at the builtin
      # layer. The result cap is stricter than OPA — OPA would return e.g. product([1e20000, 1e20000]) =
      # 1e40000 — but bounding an unbounded fold is the established DoS posture (the literal magnitude
      # cap, the re2 caps), and OPA is itself unusable at the genuinely large, non-power-of-ten end of
      # this range (>120s).
      #
      # @param numbers [Array<Numeric>]
      # @return [Number, Integer]
      # @raise [RangeError] when an intermediate overflows ENGINE_EMAX or the final magnitude exceeds
      #   MAX_MAGNITUDE_EXPONENT; the builtin layer maps it to undefined.
      def self.product(numbers)
        binnum = multiply_all(numbers)
        raise RangeError, "product result exceeds the supported magnitude range" if magnitude_exceeds_cap?(binnum)

        from_binnum(binnum)
      end

      # Fold `numbers` through the prec-64 big.Float multiply, mapping an intermediate overflow to a
      # RangeError. The rescue is scoped to the fold — the ONLY place Flt::Num::Exception arises: the
      # engine traps Overflow, so a running product beyond ENGINE_EMAX raises here rather than
      # materializing a ~10**9-digit integer. (Underflow is not trapped: a product below the engine's
      # emin saturates to 0, as OPA's far-below values do.) Keeping the rescue off {magnitude_exceeds_cap?}
      # and {from_binnum} means an unexpected exception from those fails fast instead of masking as 0.
      #
      # @param numbers [Array<Numeric>]
      # @return [Flt::BinNum]
      def self.multiply_all(numbers)
        numbers.reduce(CONTEXT.Num(1)) do |accumulator, value|
          CONTEXT.multiply(accumulator, rational_to_binnum(from_numeric(value).exact))
        end
      rescue Flt::Num::Exception => e
        raise RangeError, "product overflows the supported magnitude range (#{e.message})"
      end
      private_class_method :multiply_all

      # Whether a finite BinNum's base-10 order of magnitude exceeds MAX_MAGNITUDE_EXPONENT, computed
      # from its binary exponent and 64-bit coefficient alone — O(1), and crucially WITHOUT building the
      # full decimal expansion the check exists to prevent. `coefficient.bit_length + exponent` is
      # log2(value); scaling by log10(2) gives log10(value). bit_length over-estimates log2 by < 1 bit,
      # so the bound is marginally conservative (rejects a hair early), which is the safe direction. A
      # zero or tiny/fractional result (non-positive magnitude) never trips it.
      #
      # @param binnum [Flt::BinNum]
      # @return [Boolean]
      def self.magnitude_exceeds_cap?(binnum)
        # Defense in depth: a special value (infinity/NaN) has no integer coefficient/exponent, so the
        # arithmetic below would raise a TypeError that escapes both rescues. This is unreachable today
        # (CONTEXT traps Overflow/InvalidOperation, so the fold raises before producing one), but the
        # guard keeps this method self-contained rather than silently depending on that trap config —
        # an infinity is treated as over-cap, mapping to undefined like any other overflow.
        return true if binnum.special?
        return false if binnum.zero?

        (binnum.coefficient.bit_length + binnum.exponent) * LOG10_2 > MAX_MAGNITUDE_EXPONENT
      end
      private_class_method :magnitude_exceeds_cap?

      protected

      # @return [Flt::BinNum]
      def to_binnum
        self.class.rational_to_binnum(exact)
      end

      # The exact Rational of the precision-64 binary value — what OPA's round/ceil/floor see.
      # @return [Rational, Integer]
      def binary_value
        to_binnum.to_r
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
