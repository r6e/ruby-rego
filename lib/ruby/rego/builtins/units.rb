# frozen_string_literal: true

# rubocop:disable Metrics/ModuleLength

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "../number"

module Ruby
  module Rego
    module Builtins
      # Resource-quantity parsers (units.parse, units.parse_bytes), matching OPA. `units.parse`
      # returns an integer or a value rounded to 10 decimals; `units.parse_bytes` lowercases its
      # input, multiplies, and truncates toward zero to an integer. A non-string, an empty
      # amount, an embedded space, an unrecognised unit, an unparseable amount, or a scientific
      # exponent of more than MAX_EXPONENT_DIGITS digits yields undefined.
      #
      # `units.parse` uses exact rational arithmetic and matches OPA's big.Rat byte-for-byte.
      # `units.parse_bytes` also computes with exact Rational here, but OPA's `parse_bytes` uses a
      # 64-bit big.Float (SetString → Mul → truncate toward zero), so a fractional `parse_bytes`
      # amount can diverge in BOTH directions and by an unbounded magnitude — not merely "one lower":
      # `0.001mb` → 999 in OPA, 1000 here; `9999999999.99999999995` → 10000000000 in OPA, 9999999999
      # here; and a huge `1e100000`-scale value differs in nearly every digit. Reproducing it means
      # routing `parse_bytes` through the gem's big.Float engine (Flt::BinNum), a tracked follow-up in
      # the number sweep — not this scope. Integer and binary-exact inputs are identical either way.
      module Units
        extend RegistryHelpers

        # OPA's maxExponentDigits: a scientific exponent longer than this is undefined.
        MAX_EXPONENT_DIGITS = 6

        # OPA renders a non-integer units.parse result via big.Rat.FloatString(10): exactly 10 decimal
        # places, rounded half-away-from-zero, trailing zeros kept (see float_string).
        ROUND_DECIMALS = 10
        DECIMAL_SCALE = 10**ROUND_DECIMALS

        # Upper bound on the operand length (OPA has none — it relies on Go's runtime). Guards
        # the pure-Ruby evaluator against a huge literal numeric string allocating a giant
        # bignum; an over-long operand yields undefined. (The 6-digit exponent cap already
        # bounds scientific-notation blow-up.)
        MAX_SOURCE = 1_000_000

        # Characters that continue the numeric prefix (an `e`/`E` exponent is handled apart).
        NUMERIC = "0123456789.+-"
        DIGIT = /[0-9]/
        SIGN = %w[+ -].freeze

        # Go's big.Rat.SetString decimal-float grammar (the subset reachable after number_boundary):
        # an optional sign, a mantissa with at least one digit (so a bare "." is rejected), and an
        # optional exponent that requires at least one digit (so a dangling "1e+" is rejected). Ruby's
        # Rational is both more lenient (accepts "." and "1e+") and stricter ("5.e3"), so the amount is
        # validated against this before being handed to Rational. Anchored to the whole amount.
        AMOUNT_RE = /\A[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/

        # units.parse multipliers. Note the m/M asymmetry: lowercase `m` is milli, uppercase
        # `M` is mega; every other first letter is case-insensitive. Keys are the unit with its
        # first character kept and the remainder lowercased, so `kI`/`ki` collide while `Ki`
        # stays distinct from `ki` (hence both appear below). Milli uses the IEEE-754 double of
        # 0.001 (as OPA's big.Rat.SetFloat64 does), so e.g. `1000m` yields `1.0`, not `1`.
        PARSE_UNITS = {
          "" => 1, "m" => 0.001.to_r,
          "k" => 1_000, "K" => 1_000, "M" => 1_000_000,
          "g" => 10**9, "G" => 10**9, "t" => 10**12, "T" => 10**12,
          "p" => 10**15, "P" => 10**15, "e" => 10**18, "E" => 10**18,
          "ki" => 1024, "Ki" => 1024, "mi" => 1024**2, "Mi" => 1024**2,
          "gi" => 1024**3, "Gi" => 1024**3, "ti" => 1024**4, "Ti" => 1024**4,
          "pi" => 1024**5, "Pi" => 1024**5, "ei" => 1024**6, "Ei" => 1024**6
        }.freeze

        # units.parse_bytes multipliers (the whole input is lowercased first, so keys are too).
        # Both the `b`-suffixed and bare forms are accepted; a bare `b` is NOT a unit.
        PARSE_BYTES_UNITS = {
          "" => 1, "kb" => 1000, "k" => 1000, "kib" => 1024, "ki" => 1024,
          "mb" => 10**6, "m" => 10**6, "mib" => 1024**2, "mi" => 1024**2,
          "gb" => 10**9, "g" => 10**9, "gib" => 1024**3, "gi" => 1024**3,
          "tb" => 10**12, "t" => 10**12, "tib" => 1024**4, "ti" => 1024**4,
          "pb" => 10**15, "p" => 10**15, "pib" => 1024**5, "pi" => 1024**5,
          "eb" => 10**18, "e" => 10**18, "eib" => 1024**6, "ei" => 1024**6
        }.freeze

        UNITS_FUNCTIONS = {
          "units.parse" => { arity: 1, handler: :parse },
          "units.parse_bytes" => { arity: 1, handler: :parse_bytes }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, UNITS_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # Parses an SI/binary quantity (e.g. "10K", "1.5Mi", "10m") to a number — exact rational
        # arithmetic. An integer-valued result is an exact Integer; a non-integer result is a
        # precision-preserving Number rendered to 10 decimals the way OPA's big.Rat does.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Integer, Ruby::Rego::Number]
        def self.parse(value)
          amount, unit = split(string_arg(value, "units.parse"), "units.parse")
          multiplier = PARSE_UNITS[normalize_unit(unit)] || raise_unrecognized(unit, "units.parse")
          result = parse_amount(amount, "units.parse") * multiplier # @type var result: Rational
          # Number.literal (not from_numeric/from_binnum, which route through GoNumberFormat's shortest
          # form and would strip the trailing zeros) preserves the fixed 10-decimal text verbatim; its
          # exact value is re-derived lazily from that text.
          result.denominator == 1 ? result.numerator : Number.literal(float_string(result))
        end

        # Renders an exact non-integer Rational the way Go's big.Rat.FloatString(ROUND_DECIMALS) does:
        # the value rounded to ROUND_DECIMALS decimal places (half away from zero) with exactly that
        # many fractional digits, trailing zeros kept. Pure integer arithmetic, so a large magnitude
        # loses no precision (a float64 round-trip would) — matching OPA's json.Number text byte-for-
        # byte: 3/2 -> "1.5000000000", and a value rounding to zero keeps its sign (-1e-11 ->
        # "-0.0000000000", not the integer 0, since the unrounded result is non-integer).
        # @param rational [Rational]
        # @return [String]
        def self.float_string(rational)
          integer, fraction = rounded_scaled(rational.abs).divmod(DECIMAL_SCALE)
          sign = rational.negative? ? "-" : ""
          "#{sign}#{integer}.#{fraction.to_s.rjust(ROUND_DECIMALS, "0")}"
        end
        private_class_method :float_string

        # Scales a non-negative Rational to the integer value-times-10**ROUND_DECIMALS, rounded half
        # away from zero — the rounding core of big.Rat.FloatString. Rational#round is exact (no float
        # round-trip) and its default half-up rounding is half-away-from-zero for a non-negative value.
        # @param magnitude [Rational]
        # @return [Integer]
        def self.rounded_scaled(magnitude)
          (magnitude * DECIMAL_SCALE).round
        end
        private_class_method :rounded_scaled

        # Parses a byte quantity (e.g. "10KB", "1.5GiB") to an integer, truncating toward zero.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Integer]
        def self.parse_bytes(value)
          amount, unit = split(string_arg(value, "units.parse_bytes").downcase, "units.parse_bytes")
          multiplier = PARSE_BYTES_UNITS[unit] || raise_unrecognized(unit, "units.parse_bytes")
          (parse_amount(amount, "units.parse_bytes") * multiplier).to_i
        end

        # Reads the string operand and removes every double-quote, matching OPA's
        # `strings.ReplaceAll(s, "\"", "")` (verified: a value of `1"0K` parses as `10K`).
        # @return [String]
        def self.string_arg(value, context)
          Base.assert_type(value, expected: StringValue, context: context)
          string = value.value
          raise_too_long(context) if string.length > MAX_SOURCE
          # A valid quantity is pure ASCII (ASCII digits + ASCII unit letters); any non-ASCII or
          # invalid-encoding byte cannot form a recognized number+unit, so it is undefined in OPA.
          # The guard also keeps the String#delete/downcase/each_char below from raising
          # ArgumentError on an invalid-UTF-8 operand — an exception that would escape as a DoS.
          raise_amount(context) unless string.ascii_only?

          string.delete('"')
        end
        private_class_method :string_arg

        # Splits "<amount><unit>" at the first non-numeric character. An embedded space or an
        # over-long scientific exponent is undefined, as is a missing amount.
        # @return [Array(String, String)]
        def self.split(string, context)
          raise_spaces(context) if string.include?(" ")

          boundary = number_boundary(string, context) || string.length
          amount = string[0...boundary] || ""
          raise_no_amount(context) if amount.empty?

          [amount, string[boundary..] || ""]
        end
        private_class_method :split

        # Index of the first character that begins the unit, or nil if the whole string is
        # numeric. Mirrors OPA's extractNumAndUnit, including the exponent-length guard.
        # @return [Integer, nil]
        def self.number_boundary(string, context)
          string.each_char.with_index do |char, index|
            next guard_exponent(string, index, context) if exponent_at?(string, index)
            return index unless NUMERIC.include?(char)
          end
          nil
        end
        private_class_method :number_boundary

        # True when `e`/`E` at `index` opens a scientific exponent (followed by a digit or sign).
        # @return [bool]
        def self.exponent_at?(string, index)
          return false unless %w[e E].include?(string[index])

          nxt = string[index + 1] || ""
          DIGIT.match?(nxt) || SIGN.include?(nxt)
        end
        private_class_method :exponent_at?

        # Rejects (→ undefined) an exponent with more than MAX_EXPONENT_DIGITS digits.
        # @return [void]
        def self.guard_exponent(string, index, context)
          start = index + 1
          start += 1 if SIGN.include?(string[start])
          finish = start
          finish += 1 while DIGIT.match?(string[finish] || "")
          raise_exponent(context) if finish - start > MAX_EXPONENT_DIGITS
        end
        private_class_method :guard_exponent

        # Keeps the unit's first character and lowercases the rest, so `m`/`M` (and `Ki`/`ki`)
        # stay distinct while `kI`/`ki` and `KI`/`Ki` collapse (matching OPA).
        # @return [String]
        def self.normalize_unit(unit)
          return unit if unit.length <= 1

          unit[0].to_s + (unit[1..] || "").downcase
        end
        private_class_method :normalize_unit

        # Parses the numeric amount exactly the way OPA's big.Rat.SetString does. Ruby's Rational
        # accepts a different grammar, so the amount is first validated against AMOUNT_RE (Go's
        # reachable decimal-float grammar) — rejecting forms Ruby would misread, e.g. a bare dot
        # ("." -> 0) or a dangling exponent ("1e+" -> 1), both of which Go rejects. An accepted form
        # is then normalized for Ruby's Rational, which rejects a trailing dot directly before an
        # exponent ("5.e3", which Go reads as 5e3): a "." sitting just before "e"/"E" becomes ".0".
        # @return [Rational]
        def self.parse_amount(string, context)
          raise ArgumentError unless AMOUNT_RE.match?(string)

          Rational(string.sub(/\.(?=[eE])/, ".0"))
        rescue ArgumentError, ZeroDivisionError
          raise_amount(context)
        end
        private_class_method :parse_amount

        # @return [void]
        def self.raise_unrecognized(unit, context)
          Base.raise_argument_error(
            "unit #{unit} not recognized", expected: "a recognized unit suffix", actual: unit, context: context
          )
        end
        private_class_method :raise_unrecognized

        # @return [void]
        def self.raise_too_long(context)
          Base.raise_argument_error(
            "resource string exceeds maximum length #{MAX_SOURCE}",
            expected: "length <= #{MAX_SOURCE}", actual: "too long", context: context
          )
        end
        private_class_method :raise_too_long

        # @return [void]
        def self.raise_spaces(context)
          Base.raise_argument_error(
            "spaces not allowed in resource strings", expected: "no spaces", actual: "a space", context: context
          )
        end
        private_class_method :raise_spaces

        # @return [void]
        def self.raise_no_amount(context)
          Base.raise_argument_error(
            "no amount provided", expected: "a numeric amount", actual: "none", context: context
          )
        end
        private_class_method :raise_no_amount

        # @return [void]
        def self.raise_amount(context)
          Base.raise_argument_error(
            "could not parse amount to a number", expected: "a number", actual: "unparseable", context: context
          )
        end
        private_class_method :raise_amount

        # @return [void]
        def self.raise_exponent(context)
          Base.raise_argument_error(
            "exponent too large", expected: "<= #{MAX_EXPONENT_DIGITS} exponent digits",
                                  actual: "too many", context: context
          )
        end
        private_class_method :raise_exponent
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength

Ruby::Rego::Builtins::Units.register!
