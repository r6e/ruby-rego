# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Times
        module GoLayout
          # The composition half of the parser: resolves the accumulated broken-down fields to
          # epoch nanoseconds, applying AM/PM, the day-of-year conversion, the zone offset, and
          # the calendar/range validation Go's parse defers to the end. Split from the driver so
          # parser.rb stays under RubyCritic's complexity budget; the class path is unchanged.
          # :reek:InstanceVariableAssumption -- the ivars are set in Parser#initialize (parser.rb);
          # this reopen only reads/updates the already-established broken-down fields.
          # rubocop:disable Naming/PredicateMethod -- resolve_date/apply_yday return a success
          # boolean for control flow (false aborts the parse); they are not predicates.
          class Parser
            private

            # Resolve the accumulated fields to epoch nanoseconds (UTC), applying AM/PM, the
            # day-of-year conversion, the zone offset, and the calendar/range validation Go's
            # parse defers to the end. nil when the date is invalid or out of representable range.
            def compose
              return nil unless resolve_date

              apply_meridiem
              seconds = epoch_seconds
              return nil if seconds.nil?

              nanos = (seconds * NANOS_PER_SECOND) + @nsec
              nanos if nanos.between?(INT64_MIN, INT64_MAX)
            end

            # Fix the month/day from the day-of-year when given (validating any explicit
            # month/day agree), else default them, then range-check the calendar date.
            def resolve_date
              return false unless apply_yday

              @month = 1 if @month.negative?
              @day = 1 if @day.negative?
              Date.valid_date?(@year, @month, @day)
            end

            def apply_yday
              return true if @yday.negative?

              date = Date.ordinal(@year, @yday)
              return false if @month >= 1 && @month != date.month
              return false if @day >= 1 && @day != date.day

              @month = date.month
              @day = date.day
              true
            rescue Date::Error
              false
            end

            # Go: a PM hour below 12 advances by 12; a 12 AM hour wraps to 0.
            def apply_meridiem
              if @pm && @hour < 12
                @hour += 12
              elsif @am && @hour == 12
                @hour = 0
              end
            end

            def epoch_seconds
              ::Time.utc(@year, @month, @day, @hour, @min, @sec).to_i - (@zone_offset || 0)
            rescue RangeError
              nil
            end
          end
          # rubocop:enable Naming/PredicateMethod
        end
      end
    end
  end
end
