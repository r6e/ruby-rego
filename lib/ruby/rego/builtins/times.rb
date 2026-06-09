# frozen_string_literal: true

require "time"
require "date"
require "tzinfo"
require "tzinfo/data" # pin the Ruby (tzinfo-data) timezone database explicitly, not host zoneinfo
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
      #
      # date/clock/weekday decompose an instant given as nanoseconds since the Unix epoch — a bare
      # number (interpreted as UTC) or `[ns, tz]` where `tz` is `""`/`"UTC"`, `"Local"`, or an IANA
      # name (resolved via tzinfo). A third array element (a layout, used only by time.format) is
      # accepted and ignored. A non-integer/out-of-int64 ns, a non-string tz, or an unknown zone is
      # undefined.
      #
      # diff returns the calendar difference between two such instants as a non-negative
      # [years, months, days, hours, minutes, seconds] tuple, decomposed in the first operand's zone.
      # :reek:TooManyConstants
      module Times
        extend RegistryHelpers

        INT64_MAX = (2**63) - 1
        INT64_MIN = -(2**63)
        NANOS_PER_SECOND = 1_000_000_000

        # Go's Weekday.String() names, indexed by Ruby's Time#wday (Sunday == 0); kept as an
        # explicit table that mirrors Go's spelling rather than deriving the name another way.
        DAY_NAMES = %w[Sunday Monday Tuesday Wednesday Thursday Friday Saturday].freeze

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
          "time.parse_duration_ns" => { arity: 1, handler: :parse_duration_ns },
          "time.date" => { arity: 1, handler: :date },
          "time.clock" => { arity: 1, handler: :clock },
          "time.weekday" => { arity: 1, handler: :weekday },
          "time.diff" => { arity: 2, handler: :diff },
          "time.add_date" => { arity: 4, handler: :add_date }
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
        # That explicitness is what pushes ABC (and, with the RangeError guard, length) over default.
        # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
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
        rescue RangeError
          # A platform whose Time can't represent this year (e.g. a 32-bit time_t build) — undefined,
          # not a crash. On a 64-bit Time the range is bounded later by `bounded`.
          nil
        end
        # rubocop:enable Metrics/AbcSize, Metrics/MethodLength
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

        # @param value [Ruby::Rego::Value] ns, or [ns, tz] (an optional ignored layout may follow)
        # @return [Array(Integer, Integer, Integer)] [year, month, day]
        def self.date(value)
          time = tz_instant(value, "time.date")
          [time.year, time.month, time.day]
        end

        # @return [Array(Integer, Integer, Integer)] [hour, minute, second]
        def self.clock(value)
          time = tz_instant(value, "time.clock")
          [time.hour, time.min, time.sec]
        end

        # @return [String] the English weekday name
        def self.weekday(value)
          DAY_NAMES.fetch(tz_instant(value, "time.weekday").wday)
        end

        # Adds years/months/days (Go's Time.AddDate) to an instant, keeping the wall clock and zone,
        # and returns the result as nanoseconds. The shifted calendar date is normalised the way Go's
        # time.Date does — overflow rolls forward (Jan 31 + 1mo -> Mar 2/3), not clamped — and the
        # wall clock is re-anchored in the operand's zone (a DST gap/overlap is resolved exactly as
        # Go's time.Date does). Out of the int64 range, or a non-integer count, is undefined.
        # @param value [Ruby::Rego::Value] ns or [ns, tz]
        # @return [Integer, Ruby::Rego::UndefinedValue]
        # :reek:LongParameterList
        # :reek:TooManyStatements
        def self.add_date(value, years_value, months_value, days_value)
          nanos, zone = operand_parts(value, "time.add_date")
          years = int_arg(years_value, "time.add_date")
          months = int_arg(months_value, "time.add_date")
          days = int_arg(days_value, "time.add_date")
          fields = shift_date(localize(nanos, zone), years, months, days)
          bounded(reconstruct_ns(fields, zone, nanos % NANOS_PER_SECOND)) || UndefinedValue.new
        rescue RangeError
          UndefinedValue.new
        end

        # @return [Integer] the number as an integer, or raises (-> undefined) if it has a fraction
        def self.int_arg(value, context)
          Base.assert_type(value, expected: NumberValue, context: context)
          integer_value(value.value) || raise_time_error(context)
        end
        private_class_method :int_arg

        # The instant's wall fields shifted by years/months/days, normalised like Go's time.Date:
        # the month folds into the year, then the day offset is applied via Date arithmetic so an
        # out-of-range day rolls forward into the following month rather than clamping.
        # @return [Array(Integer, Integer, Integer, Integer, Integer, Integer)] y, m, d, h, min, sec
        # rubocop:disable Metrics/AbcSize
        # :reek:TooManyStatements
        # :reek:LongParameterList
        def self.shift_date(instant, years, months, days)
          year = instant.year + years
          month_index = (instant.month + months) - 1
          year += month_index.div(12)
          month = (month_index % 12) + 1
          date = Date.new(year, month, 1) + (instant.day - 1 + days)
          [date.year, date.month, date.day, instant.hour, instant.min, instant.sec]
        end
        # rubocop:enable Metrics/AbcSize
        private_class_method :shift_date

        # The Unix-epoch nanoseconds of a wall clock (y, m, d, h, min, sec + nsec) in `zone`.
        # :reek:TooManyStatements
        def self.reconstruct_ns(fields, zone, nsec)
          year, month, day, hour, minute, second = fields
          naive = ::Time.utc(year, month, day, hour, minute, second)
          wall_seconds = naive.to_i
          seconds = case zone
                    when "", "UTC" then wall_seconds
                    when "Local" then wall_seconds - local_offset_at(naive)
                    else wall_seconds - zone_offset_at(TZInfo::Timezone.get(zone), naive)
                    end
          (seconds * NANOS_PER_SECOND) + nsec
        end
        private_class_method :reconstruct_ns

        # The zone offset (seconds) to apply to a wall-clock-as-UTC instant, ported from Go's
        # time.Date: look up the offset at the naive instant, then if applying it would cross into an
        # adjacent period (a DST gap/overlap), re-look-up at that boundary — yielding Go's exact
        # gap (post-transition offset) and overlap (first occurrence) resolution.
        # :reek:TooManyStatements
        def self.zone_offset_at(timezone, naive)
          period = timezone.period_for_utc(naive)
          offset = period.offset.utc_total_offset
          utc = naive.to_i - offset
          starts = period.starts_at&.to_i
          ends = period.ends_at&.to_i
          return offset_at_unix(timezone, starts - 1) if starts && utc < starts
          return offset_at_unix(timezone, ends) if ends && utc >= ends

          offset
        end
        private_class_method :zone_offset_at

        # The zone's offset (seconds) at the given Unix second. (period.starts_at/ends_at are
        # TZInfo::Timestamps without arithmetic, so the re-lookup goes through a Unix second.)
        def self.offset_at_unix(timezone, unix)
          timezone.period_for_utc(::Time.at(unix).utc).offset.utc_total_offset
        end
        private_class_method :offset_at_unix

        # Go's time.Local resolution for a wall clock: the process-local offset at the naive-as-UTC
        # instant, re-checked at the candidate, so a DST gap/overlap resolves as Go's time.Date does.
        # Ruby's Time.local (POSIX mktime) instead picks the standard-time occurrence for an overlap,
        # which would diverge, so the offset is computed via getlocal rather than constructed.
        def self.local_offset_at(naive)
          unix = naive.to_i
          offset = ::Time.at(unix).getlocal.utc_offset
          rechecked = ::Time.at(unix - offset).getlocal.utc_offset
          rechecked == offset ? offset : rechecked
        end
        private_class_method :local_offset_at

        # The calendar difference between two instants as [years, months, days, hours, minutes,
        # seconds], all non-negative — matching OPA (which uses icza/gox's algorithm). Both instants
        # are decomposed in the FIRST operand's timezone (Go realigns the second to the first's
        # location), then a borrow-normalised component subtraction is taken from the earlier to the
        # later. The second operand's zone is still resolved (and so validated) even though the
        # decomposition uses the first's.
        # @param left [Ruby::Rego::Value] ns or [ns, tz]
        # @param right [Ruby::Rego::Value] ns or [ns, tz]
        # @return [Array(Integer, Integer, Integer, Integer, Integer, Integer)]
        # :reek:TooManyStatements
        def self.diff(left, right)
          left_nanos, zone = operand_parts(left, "time.diff")
          right_nanos, right_zone = operand_parts(right, "time.diff")
          in_zone(utc_instant(0), right_zone, "time.diff") # validate the 2nd zone too
          left_nanos, right_nanos = right_nanos, left_nanos if left_nanos > right_nanos # order earlier->later
          diff_components(localize(left_nanos, zone), localize(right_nanos, zone))
        rescue RangeError
          raise_time_error("time.diff")
        end

        # The instant `nanos` as a Ruby Time decomposed in `zone`.
        def self.localize(nanos, zone)
          in_zone(utc_instant(nanos), zone, "time.diff")
        end
        private_class_method :localize

        # icza/gox's borrow-normalised component difference (earlier -> later), kept as a literal
        # port of the Go algorithm. The day borrow uses the earlier date's month length, exactly as
        # the original does; that sequence of borrows is what trips the ABC/length cops.
        # @return [Array(Integer, Integer, Integer, Integer, Integer, Integer)]
        # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
        # :reek:TooManyStatements
        def self.diff_components(earlier, later)
          earlier_year = earlier.year
          earlier_month = earlier.month
          year = later.year - earlier_year
          month = later.month - earlier_month
          day = later.day - earlier.day
          hour = later.hour - earlier.hour
          minute = later.min - earlier.min
          second = later.sec - earlier.sec
          minute, second = borrow(minute, second, 60)
          hour, minute = borrow(hour, minute, 60)
          day, hour = borrow(day, hour, 24)
          month, day = borrow(month, day, days_in_month(earlier_year, earlier_month))
          year, month = borrow(year, month, 12)
          [year, month, day, hour, minute, second]
        end
        # rubocop:enable Metrics/AbcSize, Metrics/MethodLength
        private_class_method :diff_components

        # If `low` is negative, carry one unit (`base`) down from `high`.
        # @return [[Integer, Integer]] the adjusted [high, low]
        def self.borrow(high, low, base)
          return [high, low] unless low.negative?

          [high - 1, low + base]
        end
        private_class_method :borrow

        def self.days_in_month(year, month)
          Date.new(year, month, -1).day
        end
        private_class_method :days_in_month

        # The instant (a Ruby Time in the requested zone) for a ns / [ns, tz] operand. Raises a
        # BuiltinArgumentError (→ undefined) on a bad number, type, or zone.
        def self.tz_instant(value, context)
          nanos, zone = operand_parts(value, context)
          in_zone(utc_instant(nanos), zone, context)
        rescue RangeError
          # Defensive, consistent with epoch_seconds: a platform whose Time can't represent this
          # instant (e.g. a 32-bit time_t build) is undefined, not a crash. The ns is already
          # int64-bounded, so a 64-bit Time never reaches here.
          raise_time_error(context)
        end
        private_class_method :tz_instant

        # @return [[Integer, String]] the nanoseconds and the timezone name
        # :reek:TooManyStatements
        def self.operand_parts(value, context)
          return [require_nanos(value, context), "UTC"] unless value.is_a?(ArrayValue)

          elements = value.value.to_a
          raise_time_error(context) if elements.empty?
          count = elements.length
          nanos = require_nanos(elements[0], context)
          zone = count > 1 ? require_zone_name(elements[1], context) : "UTC"
          # A third element is a layout (only meaningful to time.format); validated as a string but
          # ignored here. Any further elements are ignored entirely, matching OPA's tzTime.
          require_zone_name(elements[2], context) if count > 2
          [nanos, zone]
        end
        private_class_method :operand_parts

        # The operand as an int64 nanosecond count. OPA converts via big.Float.Int64 and rejects a
        # non-integer or out-of-range value, so a fractional or oversized number is undefined.
        def self.require_nanos(value, context)
          Base.assert_type(value, expected: NumberValue, context: context)
          nanos = integer_value(value.value)
          return nanos if nanos&.between?(INT64_MIN, INT64_MAX)

          raise_time_error(context)
        end
        private_class_method :require_nanos

        # @return [Integer, nil] the number as an integer if it has no fractional part, else nil
        def self.integer_value(number)
          return number if number.is_a?(Integer)
          return nil unless number.is_a?(Float) && number.finite?

          truncated = number.to_i
          number == truncated ? truncated : nil
        end
        private_class_method :integer_value

        def self.require_zone_name(value, context)
          Base.assert_type(value, expected: StringValue, context: context)
          value.value
        end
        private_class_method :require_zone_name

        # The instant `nanos` nanoseconds after the Unix epoch as a UTC Ruby Time.
        def self.utc_instant(nanos)
          ::Time.at(0, nanos, :nanosecond).utc
        end
        private_class_method :utc_instant

        # Converts a UTC time to the requested zone: "" / "UTC" stay UTC, "Local" uses the process's
        # local zone (Go's time.Local), any other name is an IANA identifier resolved via tzinfo.
        def self.in_zone(utc_time, zone, context)
          case zone
          when "", "UTC" then utc_time
          when "Local" then utc_time.getlocal
          else TZInfo::Timezone.get(zone).to_local(utc_time)
          end
        rescue TZInfo::InvalidTimezoneIdentifier, TZInfo::DataSourceNotFound
          # Unknown zone, or (defensively, since tzinfo-data is a dependency) no tz database at all.
          raise_time_error(context)
        end
        private_class_method :in_zone

        def self.raise_time_error(context)
          Base.raise_argument_error("invalid #{context} operand",
                                    expected: "ns or [ns, tz]", actual: "invalid", context: context)
        end
        private_class_method :raise_time_error

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
        # @return [[Integer, String]] the multiplier (nil if the unit is unknown) and the rest
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
