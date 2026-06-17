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
          # whole parse as undefined, matching Go returning a *ParseError. The field consumers,
          # zone grammar, and composition live in the parser/ sub-files (required below); this
          # file holds the driver — the layout walk and token dispatch — plus the shared tables.
          # :reek:TooManyInstanceVariables -- the broken-down fields Go's parse() also carries.
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

            # True when `char` is a single ASCII digit. Shared by the field and zone consumers
            # in the parser/ sub-files; kept here so it is defined before any sub-file uses it.
            def digit?(char)
              !char.nil? && char.between?("0", "9")
            end
          end
          # rubocop:enable Naming/PredicateMethod
        end
      end
    end
  end
end

require_relative "parser/fields"
require_relative "parser/consumers"
require_relative "parser/zones"
require_relative "parser/compose"
