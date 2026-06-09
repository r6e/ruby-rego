# frozen_string_literal: true

require "time"
require "date"
require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

# rubocop:disable Metrics/ModuleLength
module Ruby
  module Rego
    module Builtins
      # Time parsing builtins (time.parse_rfc3339_ns, time.parse_duration_ns), matching OPA.
      # Both return nanoseconds (an integer); a non-string or an unparseable input is undefined.
      #
      # parse_rfc3339_ns parses a strict RFC 3339 timestamp (uppercase `T`/`Z`, a required zone of
      # `Z` or `±HH:MM`, a fractional second of any length truncated to nanoseconds, a valid
      # calendar date/time) the way Go's time.Parse(time.RFC3339) does, and is undefined when the
      # instant falls outside the int64-nanosecond range (~1677–2262).
      #
      # parse_duration_ns parses a Go duration (signed, fractional, units ns/us/µs/ms/s/m/h, with
      # `0` a valid zero) and OPA's `d`/`w`/`y` extension (rewritten to 24h/168h/8760h, matching
      # OPA's float-through-hours path). The total must fit int64 nanoseconds.
      # :reek:TooManyConstants
      module Times
        extend RegistryHelpers

        INT64_MAX = (2**63) - 1
        INT64_MIN = -(2**63)
        NANOS_PER_SECOND = 1_000_000_000

        # Nanoseconds per standard Go duration unit.
        DURATION_UNITS = {
          "ns" => 1, "us" => 1_000, "µs" => 1_000, "μs" => 1_000, "ms" => 1_000_000,
          "s" => NANOS_PER_SECOND, "m" => 60 * NANOS_PER_SECOND, "h" => 3600 * NANOS_PER_SECOND
        }.freeze

        # OPA's extended units, expressed as a multiple of hours.
        EXTENDED_HOURS = { "d" => 24, "w" => 7 * 24, "y" => 365 * 24 }.freeze

        RFC3339 = /\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})\z/

        TIME_FUNCTIONS = {
          "time.parse_rfc3339_ns" => { arity: 1, handler: :parse_rfc3339_ns },
          "time.parse_duration_ns" => { arity: 1, handler: :parse_duration_ns }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, TIME_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param value [Ruby::Rego::Value]
        # @return [Integer, Ruby::Rego::UndefinedValue]
        def self.parse_rfc3339_ns(value)
          match = RFC3339.match(string_arg(value, "time.parse_rfc3339_ns"))
          nanos = match && rfc3339_nanos(match)
          nanos || UndefinedValue.new
        end

        # The instant as nanoseconds since the Unix epoch, or nil if the date/time is invalid
        # (Ruby's Time would silently normalise an out-of-range hour/day, so the fields are
        # validated explicitly) or outside the int64 range. Over-long fractions truncate to ns.
        # @return [Integer, nil]
        def self.rfc3339_nanos(match)
          seconds = epoch_seconds(match)
          seconds && bounded((seconds * NANOS_PER_SECOND) + fraction_nanos(match[7]))
        end
        private_class_method :rfc3339_nanos

        # The Unix-epoch seconds for a valid RFC 3339 match, or nil if a field or the zone offset
        # is out of range. Every field is range-checked explicitly because Ruby's Time silently
        # normalises an out-of-range hour/day, and the offset is applied by hand because Go (unlike
        # Ruby's Time) accepts offset fields up to 24h/60m (e.g. `+24:60`) and Ruby would raise.
        # Each field is a separate `match[n].to_i` local so Steep types it Integer (String?#to_i);
        # destructuring `captures.take(6).map(&:to_i)` instead yields Integer?, rejected downstream.
        # That explicitness is what pushes ABC over the cop's default.
        # rubocop:disable Metrics/AbcSize
        # :reek:TooManyStatements
        def self.epoch_seconds(match)
          year = match[1].to_i
          month = match[2].to_i
          day = match[3].to_i
          hour = match[4].to_i
          minute = match[5].to_i
          second = match[6].to_i
          return nil unless Date.valid_date?(year, month, day) && hour < 24 && minute < 60 && second < 60

          offset = zone_offset(match[8].to_s)
          offset && (::Time.utc(year, month, day, hour, minute, second).to_i - offset)
        end
        # rubocop:enable Metrics/AbcSize
        private_class_method :epoch_seconds

        # The zone's signed offset in seconds, or nil if out of range. Go's RFC 3339 parser accepts
        # an offset hour up to 24 and minute up to 60 (each field, independently — `+24:60` is valid
        # but `+25:00` is not) and applies `sign * (hour*3600 + minute*60)`.
        # :reek:TooManyStatements
        def self.zone_offset(zone)
          return 0 if zone == "Z"

          hours = zone[1, 2].to_i
          minutes = zone[4, 2].to_i
          return nil if hours > 24 || minutes > 60

          (zone.start_with?("-") ? -1 : 1) * ((hours * 3600) + (minutes * 60))
        end
        private_class_method :zone_offset

        # The fractional-second capture (e.g. ".123") as nanoseconds, truncated to 9 digits.
        def self.fraction_nanos(fraction)
          fraction ? fraction[1, 9].to_s.ljust(9, "0").to_i : 0
        end
        private_class_method :fraction_nanos

        # @return [Integer, nil]
        def self.bounded(nanos)
          nanos if nanos.between?(INT64_MIN, INT64_MAX)
        end
        private_class_method :bounded

        # @param value [Ruby::Rego::Value]
        # @return [Integer, Ruby::Rego::UndefinedValue]
        def self.parse_duration_ns(value)
          parse_extended_duration(string_arg(value, "time.parse_duration_ns")) || UndefinedValue.new
        end

        # @return [Integer, nil]
        def self.parse_extended_duration(string)
          return nil if string.empty?
          return parse_go_duration(string) unless string.match?(/[dwy]/)

          rewritten = rewrite_extended(string)
          rewritten && parse_go_duration(rewritten)
        end
        private_class_method :parse_extended_duration

        # Rewrites any d/w/y segments to an equivalent `<hours>h` segment (value * coefficient,
        # via float, as OPA does), leaving standard segments untouched. Nil if not well-formed.
        # @return [String, nil]
        # :reek:TooManyStatements
        def self.rewrite_extended(string)
          sign = string.start_with?("+", "-") ? string[0].to_s : ""
          body = sign.empty? ? string : string[1..].to_s
          segments = scan_segments(body)
          return nil unless segments

          sign + segments.map { |pair| rewrite_segment(pair[0].to_s, pair[1].to_s) }.join
        end
        private_class_method :rewrite_extended

        # The (digits, unit) capture pairs of `body`, or nil if it is not a clean sequence of them.
        # Both capture groups always participate, so each pair is a two-String array.
        # @return [Array[Array[String]], nil]
        def self.scan_segments(body)
          segments = body.scan(/(\d*\.?\d*)([a-zµμ]+)/) # @type var segments: Array[Array[String]]
          return nil if segments.empty?

          segments if segments.map { |pair| "#{pair[0]}#{pair[1]}" }.join == body
        end
        private_class_method :scan_segments

        # @return [String]
        # :reek:DuplicateMethodCall
        def self.rewrite_segment(digits, unit)
          coefficient = EXTENDED_HOURS[unit]
          return digits + unit unless coefficient

          "#{Float(digits) * coefficient}h"
        rescue ArgumentError
          # A malformed numeric (e.g. "1.2.3") keeps the segment as-is; parse_go_duration rejects it.
          digits + unit
        end
        private_class_method :rewrite_segment

        # A faithful port of Go's time.ParseDuration: signed, fractional, repeated value+unit
        # segments, with `0` the sole unit-less form. The magnitude is summed exactly (Ruby's
        # integers don't wrap) and the signed result must fit int64, else nil — matching Go,
        # which errors on overflow but allows the negative minimum (-2^63).
        # :reek:TooManyStatements
        def self.parse_go_duration(string)
          negative, rest = split_sign(string)
          return 0 if rest == "0"
          return nil if rest.empty?

          total = sum_segments(rest)
          total && bounded(negative ? -total : total)
        end
        private_class_method :parse_go_duration

        # The summed nanoseconds of every value+unit segment, or nil on a malformed segment.
        # :reek:NilCheck
        def self.sum_segments(rest)
          total = 0
          until rest.empty?
            value, rest = parse_segment(rest)
            return nil if value.nil?

            total += value
          end
          total
        end
        private_class_method :sum_segments

        # @return [[bool, String]]
        def self.split_sign(string)
          negative = string.start_with?("-")
          return [negative, string[1..].to_s] if negative || string.start_with?("+")

          [false, string]
        end
        private_class_method :split_sign

        # One value+unit segment's nanosecond contribution and the remaining string, or [nil, _].
        # :reek:TooManyStatements
        # :reek:NilCheck
        def self.parse_segment(string)
          return [nil, string] unless string.start_with?(".") || digit?(string[0])

          integer, after_int, had_int = leading_int(string)
          fraction, scale, after_frac = parse_fraction(after_int)
          return [nil, string] unless had_int || scale > 1

          unit_ns, rest = take_unit(after_frac)
          return [nil, string] if unit_ns.nil?

          [segment_nanos(integer, fraction, scale, unit_ns), rest]
        end
        private_class_method :parse_segment

        # @return [[Integer, Integer, String]] fraction digits as (value, scale), and the rest
        def self.parse_fraction(string)
          return leading_fraction(string[1..].to_s) if string.start_with?(".")

          [0, 1, string]
        end
        private_class_method :parse_fraction

        # The segment's exact nanoseconds (Go's int_part*unit + int64(frac*unit/scale); the
        # signed-int64 bound is enforced once, on the running total).
        # @return [Integer]
        # :reek:LongParameterList
        def self.segment_nanos(integer, fraction, scale, unit_ns)
          value = integer * unit_ns
          value += (fraction.to_f * (unit_ns.to_f / scale)).to_i if fraction.positive?
          value
        end
        private_class_method :segment_nanos

        # @return [[Integer, String, bool]]
        def self.leading_int(string)
          digits = string[/\A\d*/].to_s
          return [0, string, false] if digits.empty?

          [digits.to_i, string[digits.length..].to_s, true]
        end
        private_class_method :leading_int

        # Go's leadingFraction: the fractional digits as (x, scale), ignoring digits once x would
        # overflow. @return [[Integer, Integer, String]]
        # :reek:TooManyStatements
        def self.leading_fraction(string)
          digits = string[/\A\d*/].to_s
          accumulated = 0
          scale = 1
          digits.each_char do |char|
            next if accumulated > (INT64_MAX - 9) / 10

            accumulated = (accumulated * 10) + (char.ord - 48)
            scale *= 10
          end
          [accumulated, scale, string[digits.length..].to_s]
        end
        private_class_method :leading_fraction

        # The unit (run of non-digit, non-dot chars) as its nanosecond multiplier, and the rest.
        # @return [[Integer, nil], String]
        def self.take_unit(string)
          unit = string[/\A[^0-9.]*/].to_s
          [DURATION_UNITS[unit], string[unit.length..].to_s]
        end
        private_class_method :take_unit

        # :reek:NilCheck
        def self.digit?(char)
          !char.nil? && char >= "0" && char <= "9"
        end
        private_class_method :digit?

        def self.string_arg(value, context)
          Base.assert_type(value, expected: StringValue, context: context)
          value.value
        end
        private_class_method :string_arg
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength

Ruby::Rego::Builtins::Times.register!
