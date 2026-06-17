# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Times
        module GoLayout
          # The per-token field consumers of the parser: each reads one layout token's value
          # from the input via the field primitives, accumulates the broken-down field, and
          # returns a success boolean (false aborts the parse). Split from the primitives and the
          # driver so each file stays under RubyCritic's complexity budget; class path unchanged.
          # rubocop:disable Naming/PredicateMethod -- the consume_* helpers return a success
          # boolean for control flow (false aborts the parse); they are not predicates.
          # :reek:InstanceVariableAssumption -- the ivars are set in Parser#initialize (parser.rb);
          # this reopen only reads/updates the already-established broken-down fields.
          class Parser
            private

            def consume_year2
              return false unless digit?(@value[0]) && digit?(@value[1])

              number = @value[0, 2].to_i
              @value = @value[2..]
              @year = number >= 69 ? number + 1900 : number + 2000
              true
            end

            def consume_long_year
              @year = getnum4
              !@year.nil?
            end

            def consume_month(fixed)
              @month = getnum(fixed) || (return false)
              @month.between?(1, 12)
            end

            # A (long or short) month name; lookup yields a 1..12 index or nil.
            def consume_month_name(names)
              @month = lookup(names)
              !@month.nil?
            end

            def consume_day(fixed)
              @day = getnum(fixed)
              !@day.nil?
            end

            def consume_year_day(fixed)
              @yday = getnum3(fixed)
              !@yday.nil?
            end

            def consume_hour24
              @hour = getnum(false) || (return false)
              @hour.between?(0, 23)
            end

            def consume_hour12(fixed)
              @hour = getnum(fixed) || (return false)
              @hour.between?(0, 12)
            end

            def consume_minute(fixed)
              @min = getnum(fixed) || (return false)
              @min.between?(0, 59)
            end

            def consume_second(fixed)
              @sec = getnum(fixed) || (return false)
              @sec.between?(0, 59)
            end

            def consume_under_day
              @value = @value[1..] if @value[0] == " "
              @day = getnum(false)
              !@day.nil?
            end

            def consume_under_year_day
              2.times { @value = @value[1..] if @value[0] == " " }
              @yday = getnum3(false)
              !@yday.nil?
            end

            # AM/PM marker (upper "PM"/"AM" or lower "pm"/"am"). Sets the half-day flag.
            def consume_meridiem(upper)
              pm, am = upper ? %w[PM AM] : %w[pm am]
              token = @value[0, 2]
              @value = @value[2..].to_s
              return (@pm = true) if token == pm
              return (@am = true) if token == am

              false
            end
          end
          # rubocop:enable Naming/PredicateMethod
        end
      end
    end
  end
end
