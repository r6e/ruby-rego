# frozen_string_literal: true

# rubocop:disable Metrics/ModuleLength

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

module Ruby
  module Rego
    module Builtins
      # Resource-quantity parsers (units.parse, units.parse_bytes), matching OPA. `units.parse`
      # returns an integer or a value rounded to 10 decimals; `units.parse_bytes` lowercases its
      # input, multiplies, and truncates toward zero to an integer. A non-string, an empty
      # amount, an embedded space, an unrecognised unit, an unparseable amount, or a scientific
      # exponent of more than MAX_EXPONENT_DIGITS digits yields undefined.
      #
      # Both use exact rational arithmetic. OPA's `units.parse` does too (big.Rat), but its
      # `units.parse_bytes` uses big.Float, so a fractional amount whose binary approximation
      # lands just below an integer truncates one lower there (e.g. `0.001mb` → 999 in OPA,
      # 1000 here — the value `units.parse("0.001M")` also gives). This is a precision artifact
      # of OPA's float path, not replicated; integer and binary-exact inputs are identical.
      module Units
        extend RegistryHelpers

        # OPA's maxExponentDigits: a scientific exponent longer than this is undefined.
        MAX_EXPONENT_DIGITS = 6

        # Upper bound on the operand length (OPA has none — it relies on Go's runtime). Guards
        # the pure-Ruby evaluator against a huge literal numeric string allocating a giant
        # bignum; an over-long operand yields undefined. (The 6-digit exponent cap already
        # bounds scientific-notation blow-up.)
        MAX_SOURCE = 1_000_000

        # Characters that continue the numeric prefix (an `e`/`E` exponent is handled apart).
        NUMERIC = "0123456789.+-"
        DIGIT = /[0-9]/
        SIGN = %w[+ -].freeze

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

        # Parses an SI/binary quantity (e.g. "10K", "1.5Mi", "10m") to a number — exact
        # rational arithmetic, yielding an integer or a value rounded to 10 decimals.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Integer, Float]
        def self.parse(value)
          amount, unit = split(string_arg(value, "units.parse"), "units.parse")
          multiplier = PARSE_UNITS[normalize_unit(unit)] || raise_unrecognized(unit, "units.parse")
          result = parse_amount(amount, "units.parse") * multiplier
          result.denominator == 1 ? result.numerator : result.round(10).to_f
        end

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

        # Parses the numeric amount exactly (decimals and scientific notation, both supported by
        # Rational); an unparseable amount yields undefined.
        # @return [Rational]
        def self.parse_amount(string, context)
          Rational(string)
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
