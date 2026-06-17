# frozen_string_literal: true

require "date"

module Ruby
  module Rego
    module Builtins
      # time.diff — icza/gox's borrow-normalised calendar difference between two instants.
      # Lives apart from the time.* core so that file stays under RubyCritic's complexity budget.
      # Reopens Times; bare references to shared helpers (operand_parts, in_zone, utc_instant,
      # localize, raise_time_error) resolve via the reopened module's lexical scope.
      module Times
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
          diff_components(localize(left_nanos, zone, "time.diff"), localize(right_nanos, zone, "time.diff"))
        rescue RangeError
          raise_time_error("time.diff")
        end

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
      end
    end
  end
end
