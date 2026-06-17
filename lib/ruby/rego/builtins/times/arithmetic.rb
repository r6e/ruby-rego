# frozen_string_literal: true

require "time"
require "date"
require "tzinfo"

module Ruby
  module Rego
    module Builtins
      # time.add_date — Go Time.AddDate calendar arithmetic with zone-aware re-anchoring.
      # Lives apart from the time.* core so that file stays under RubyCritic's complexity budget.
      # Reopens Times; bare references to shared helpers/constants (operand_parts, localize, bounded,
      # integer_value, raise_time_error, NANOS_PER_SECOND) resolve via the reopened module's scope.
      module Times
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
          fields = shift_date(localize(nanos, zone, "time.add_date"), years, months, days)
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
      end
    end
  end
end
