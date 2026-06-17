# frozen_string_literal: true

require "date"

module Ruby
  module Rego
    module Builtins
      module Times
        # The parse direction of the Go reference-time layout language — a port of Go's
        # time.Parse (src/time/format.go). The inverse of GoLayout.format: it walks the same
        # layout via `next_chunk`, matches each literal prefix against the value, and consumes
        # the value per token, accumulating the broken-down fields. Reopens GoLayout so the
        # tokenizer and constants resolve unchanged.
        #
        # Zone handling is UTC-deterministic: an explicit numeric offset (`-0700`, `Z07:00`, …)
        # or a `Z` literal shifts the instant; a named abbreviation (`MST`, `PST`, `GMT…`) is
        # accepted and consumed per Go's parseTimeZone grammar but always resolves to a 0 offset
        # — Go resolves abbreviations against the process-local zone (host-dependent and so
        # non-deterministic), and offset 0 is what `TZ=UTC opa eval` yields. See times/parse.rb.
        module GoLayout
          # Parse `value` against `layout`, returning epoch nanoseconds, or nil when the value
          # does not match the layout, a field is out of range, input is left over, or the
          # instant falls outside the representable range. A named layout (NAMED) resolves to
          # its Go string; unlike format, an empty layout is NOT defaulted (it stays the empty
          # layout, which matches only the empty value), matching OPA's time.Parse.
          def self.parse(layout, value)
            Parser.new(NAMED.fetch(layout, layout), value).run
          end

          # Per-token digit geometry for the numeric/ISO zone offsets: total source length, the
          # index of the hour/minute/second digit pairs, and the indices that must hold a colon.
          ZONE_SHAPES = {
            num_short_tz: { len: 3, hh: 1 }, iso_short_tz: { len: 3, hh: 1, z: true },
            num_tz: { len: 5, hh: 1, mm: 3 }, iso_tz: { len: 5, hh: 1, mm: 3, z: true },
            num_colon_tz: { len: 6, hh: 1, mm: 4, colons: [3] },
            iso_colon_tz: { len: 6, hh: 1, mm: 4, colons: [3], z: true },
            num_seconds_tz: { len: 7, hh: 1, mm: 3, ss: 5 },
            iso_seconds_tz: { len: 7, hh: 1, mm: 3, ss: 5, z: true },
            num_colon_seconds_tz: { len: 9, hh: 1, mm: 4, ss: 7, colons: [3, 6] },
            iso_colon_seconds_tz: { len: 9, hh: 1, mm: 4, ss: 7, colons: [3, 6], z: true }
          }.freeze

          # Walks a (layout, value) pair, accumulating broken-down time fields. One instance per
          # parse; not reused. Mirrors Go's parse(): every helper returns false/nil to abort the
          # whole parse as undefined, matching Go returning a *ParseError.
          # :reek:TooManyInstanceVariables -- the broken-down fields Go's parse() also carries.
          # rubocop:disable Metrics/ClassLength -- a faithful single-purpose port of Go's parse().
          # rubocop:disable Naming/PredicateMethod -- the consume_* helpers return a success
          # boolean for control flow (false aborts the parse); they are not predicates.
          class Parser
            # Short (3-letter) month/weekday names, derived from the long tables GoLayout uses.
            SHORT_MONTHS = MONTHS.map { |name| name[0, 3] }.freeze
            SHORT_WEEKDAYS = WEEKDAYS.map { |name| name[0, 3] }.freeze

            # @param layout [String] a Go reference-time layout (named layouts already resolved)
            # @param value [String] the timestamp text to parse
            def initialize(layout, value)
              @layout = layout
              @value = value
              @year = @hour = @min = @sec = @nsec = 0
              @month = @day = @yday = -1
              @zone_offset = nil # nil == no zone seen (Go's -1); set to a signed seconds offset
              @pm = @am = false
            end

            # @return [Integer, nil] epoch nanoseconds, or nil when the parse is undefined
            def run
              walk ? compose : nil
            end

            private

            # Consume layout chunk by chunk; false aborts the parse. After the last token the
            # value must be fully consumed (Go errors on extra text).
            def walk
              loop do
                prefix, token, rest = GoLayout.next_chunk(@layout)
                return false unless skip_prefix(prefix)
                return @value.empty? if token.nil?

                @layout = rest
                return false unless consume(token)
              end
            end

            # Match a literal layout prefix against the value, treating any run of spaces as
            # equivalent to any other (Go's skip/cutspace). False on a mismatch.
            # rubocop:disable Metrics/MethodLength
            def skip_prefix(prefix)
              until prefix.empty?
                if prefix[0] == " "
                  return false unless @value.start_with?(" ")

                  prefix = prefix.sub(/\A +/, "")
                  @value = @value.sub(/\A +/, "")
                  next
                end
                return false unless @value[0] == prefix[0]

                prefix = prefix[1..]
                @value = @value[1..]
              end
              true
            end
            # rubocop:enable Metrics/MethodLength

            # Dispatch a single token to its field consumer; a false/nil result aborts the parse.
            # The :frac token is a tuple; the zone tokens key ZONE_SHAPES; the rest are symbols.
            def consume(token)
              return consume_fraction(token) if token.is_a?(::Array)
              return consume_zone(token) if ZONE_SHAPES.key?(token)

              dispatch(token)
            end

            # rubocop:disable Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/AbcSize
            # :reek:TooManyStatements -- a flat token→consumer dispatch; clearer as one table.
            def dispatch(token)
              case token
              when :year then consume_year2
              when :long_year then consume_long_year
              when :month then consume_month_name(SHORT_MONTHS)
              when :long_month then consume_month_name(MONTHS)
              when :weekday then !lookup(SHORT_WEEKDAYS).nil?
              when :long_weekday then !lookup(WEEKDAYS).nil?
              when :num_month then consume_month(false)
              when :zero_month then consume_month(true)
              when :day then consume_day(false)
              when :zero_day then consume_day(true)
              when :under_day then consume_under_day
              when :zero_year_day then consume_year_day(true)
              when :under_year_day then consume_under_year_day
              when :hour then consume_hour24
              when :twelve_hour then consume_hour12(false)
              when :zero_twelve_hour then consume_hour12(true)
              when :minute then consume_minute(false)
              when :zero_minute then consume_minute(true)
              when :second then consume_second(false)
              when :zero_second then consume_second(true)
              when :pm_upper then consume_meridiem(true)
              when :pm_lower then consume_meridiem(false)
              when :tz then consume_named_zone
              end
            end
            # rubocop:enable Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/AbcSize

            # Read a fixed (exactly two digits) or variable (one or two digits) decimal number,
            # advancing the value. nil when no digit is present, or fewer than two when fixed.
            def getnum(fixed)
              return nil unless digit?(@value[0])

              unless digit?(@value[1])
                return nil if fixed

                single = @value[0].to_i
                @value = @value[1..]
                return single
              end
              number = @value[0, 2].to_i
              @value = @value[2..]
              number
            end

            # Read a fixed (exactly three) or variable (one to three) digit day-of-year number.
            def getnum3(fixed)
              number = 0
              count = 0
              while count < 3 && digit?(@value[count])
                number = (number * 10) + @value[count].to_i
                count += 1
              end
              return nil if count.zero? || (fixed && count != 3)

              @value = @value[count..]
              number
            end

            # Exactly four digits (the long year). nil otherwise.
            def getnum4
              return nil unless (0..3).all? { |offset| digit?(@value[offset]) }

              number = @value[0, 4].to_i
              @value = @value[4..]
              number
            end

            # Case-insensitive longest-prefix match of the value against `names` (1-based result
            # like Go's month/weekday tables start). Returns the 1-based index or nil.
            def lookup(names)
              idx = names.index { |name| @value[0, name.length].to_s.casecmp?(name) }
              return nil if idx.nil?

              @value = @value[names[idx].length..]
              idx + 1
            end

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

            # A numeric (`-0700`) or ISO (`Z07:00`) zone offset. ISO tokens accept a bare `Z`
            # for UTC; otherwise a sign and the shape's digit groups give a signed offset. The
            # offset is not range-checked (Go's parser accepts e.g. `+24:60`).
            # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity
            def consume_zone(token)
              shape = ZONE_SHAPES.fetch(token)
              return zero_zone if shape[:z] && @value[0] == "Z"
              return false if @value.length < shape[:len]

              text = @value[0, shape[:len]].to_s # non-nil: the length guard above ensures len chars
              return false unless %w[+ -].include?(text[0])
              return false unless (shape[:colons] || []).all? { |pos| text[pos] == ":" }

              apply_offset(text, shape)
            end
            # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity

            def zero_zone
              @value = @value[1..]
              @zone_offset = 0
              true
            end

            # rubocop:disable Metrics/AbcSize
            def apply_offset(text, shape)
              hh = two_digits(text, shape[:hh]) || (return false)
              mm = shape[:mm] ? (two_digits(text, shape[:mm]) || (return false)) : 0
              ss = shape[:ss] ? (two_digits(text, shape[:ss]) || (return false)) : 0
              magnitude = (hh * 3600) + (mm * 60) + ss
              @zone_offset = text[0] == "-" ? -magnitude : magnitude
              @value = @value[shape[:len]..]
              true
            end
            # rubocop:enable Metrics/AbcSize

            # A named zone abbreviation (the layout's `MST`). Consumed per Go's parseTimeZone
            # grammar; the offset is always 0 (see the module/file notes). "UTC" is taken first.
            def consume_named_zone
              if @value.start_with?("UTC")
                @value = @value[3..]
                @zone_offset = 0
                return true
              end
              length = named_zone_length(@value)
              return false if length.zero?

              @value = @value[length..]
              @zone_offset ||= 0
              true
            end

            # The length of a zone abbreviation at the head of `value` per Go's parseTimeZone,
            # or 0 if none. GMT may carry a signed hour offset; ChST/MeST are the lower-case
            # specials; otherwise a run of 3 (always), or 4/5 ending in `T` (plus WITA),
            # uppercase letters.
            # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
            def named_zone_length(value)
              return 0 if value.length < 3
              return 4 if %w[ChST MeST].include?(value[0, 4])
              return gmt_length(value) if value[0, 3] == "GMT"

              upper = uppercase_run(value)
              case upper
              when 3 then 3
              when 4 then value[3] == "T" || value[0, 4] == "WITA" ? 4 : 0
              when 5 then value[4] == "T" ? 5 : 0
              else 0
              end
            end
            # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

            def uppercase_run(value)
              run = 0
              run += 1 while run < 6 && value[run]&.between?("A", "Z")
              run
            end

            # "GMT" optionally followed by a signed one/two-digit hour (Go's parseGMT).
            def gmt_length(value)
              rest = value[3..].to_s
              return 3 if rest.empty? || !%w[+ -].include?(rest[0])

              3 + signed_offset_length(rest)
            end

            # Length of a `+`/`-` sign plus its leading integer (capped at 23, Go's
            # parseSignedOffset), or 0 if the integer would overflow that.
            def signed_offset_length(rest)
              digits = rest[1..].to_s[/\A\d+/]
              return 1 if digits.nil? || digits.to_i > 23

              1 + digits.length
            end

            # Read exactly two digits at `index`, or nil if either is not a digit.
            def two_digits(text, index)
              return nil unless digit?(text[index]) && digit?(text[index + 1])

              text[index, 2].to_i
            end

            # A run of `kind` (:zero requires exactly `digits` fraction digits; :nine takes any
            # number and may be absent entirely). Reads the leading "." or "," separator.
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

            def digit?(char)
              !char.nil? && char.between?("0", "9")
            end

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
          # rubocop:enable Metrics/ClassLength, Naming/PredicateMethod
        end
      end
    end
  end
end
