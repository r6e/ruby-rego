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

            # Only the zero-padded `002` token reaches here (the underscore-padded `__2` form
            # routes through consume_under_year_day), so the day-of-year is always 3 fixed digits.
            def consume_year_day
              @yday = getnum3(true)
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
              return false unless @sec.between?(0, 59)

              # Go's stdSecond special case: when the value carries a fractional second but the
              # layout has NO fraction token next, absorb it here (truncating to ns). When a
              # :frac token follows, that token consumes the fraction instead.
              fraction_optional unless next_token_fraction?
              true
            end

            # Whether the next layout token is the fractional-second token (the only Array-valued
            # token next_chunk emits); peeked from the not-yet-walked remainder of the layout.
            def next_token_fraction?
              _, token, = GoLayout.next_chunk(@layout)
              token.is_a?(::Array)
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

            # The fractional-second token (:frac). `:zero` (.000) requires exactly `digits`
            # fraction digits; `:nine` (.999) takes any number and may be absent entirely. Reads
            # the leading "." or "," separator and accumulates @nsec (truncated to nanoseconds).
            def consume_fraction(token)
              _, kind, digits, = token
              kind == :zero ? fraction_fixed(digits) : fraction_optional
            end

            def fraction_fixed(digits)
              return false unless %w[. ,].include?(@value[0])

              frac = @value[1, digits]
              return false unless frac && frac.length == digits && frac.each_char.all? { |char| digit?(char) }

              @nsec = frac.ljust(9, "0")[0, 9].to_i
              @value = @value[(1 + digits)..]
              true
            end

            def fraction_optional
              return true unless %w[. ,].include?(@value[0]) && digit?(@value[1])

              run = 1
              run += 1 while digit?(@value[run])
              @nsec = @value[1, run - 1].to_s.ljust(9, "0")[0, 9].to_i
              @value = @value[run..]
              true
            end
          end
          # rubocop:enable Naming/PredicateMethod
        end
      end
    end
  end
end
