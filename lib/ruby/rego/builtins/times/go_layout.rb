# frozen_string_literal: true

require "date"

module Ruby
  module Rego
    module Builtins
      module Times
        # Formats a Ruby Time using Go's reference-time layout language (the "2006-01-02 15:04:05"
        # token scheme), a direct port of Go's stdlib `time` package (`nextStdChunk` + `appendFormat`
        # + `appendNano` from src/time/format.go). Kept self-contained so the same tokenizer can drive
        # the parse direction (time.parse_ns) later. English month/weekday names are used (Go is
        # locale-independent). The tokenizer is shared with time.format/time.parse_ns via `next_chunk`.
        # rubocop:disable Metrics/ModuleLength
        module GoLayout
          # OPA's `acceptedTimeFormats` — named layouts mapped to their Go reference-time string.
          NAMED = {
            "ANSIC" => "Mon Jan _2 15:04:05 2006",
            "UnixDate" => "Mon Jan _2 15:04:05 MST 2006",
            "RubyDate" => "Mon Jan 02 15:04:05 -0700 2006",
            "RFC822" => "02 Jan 06 15:04 MST",
            "RFC822Z" => "02 Jan 06 15:04 -0700",
            "RFC850" => "Monday, 02-Jan-06 15:04:05 MST",
            "RFC1123" => "Mon, 02 Jan 2006 15:04:05 MST",
            "RFC1123Z" => "Mon, 02 Jan 2006 15:04:05 -0700",
            "RFC3339" => "2006-01-02T15:04:05Z07:00",
            "RFC3339Nano" => "2006-01-02T15:04:05.999999999Z07:00"
          }.freeze

          # The default layout when none is given (Go's time.RFC3339Nano).
          DEFAULT = NAMED.fetch("RFC3339Nano")

          MONTHS = %w[January February March April May June July August September October November December].freeze
          WEEKDAYS = %w[Sunday Monday Tuesday Wednesday Thursday Friday Saturday].freeze

          # The Go layout string for a (possibly named) layout, or the literal layout if not named.
          def self.resolve(layout)
            return DEFAULT if layout.empty?

            NAMED.fetch(layout, layout)
          end

          # @param time [Time] the instant already localised in the target zone
          # @param layout [String] a Go reference-time layout (resolved if a named constant)
          # @return [String]
          def self.format(time, layout)
            out = +""
            remaining = resolve(layout)
            until remaining.empty?
              prefix, token, remaining = next_chunk(remaining)
              out << prefix
              break if token.nil?

              out << emit(time, token)
            end
            out
          end

          # A port of Go's nextStdChunk: the next [literal prefix, token, suffix]. `token` is a Symbol
          # for a fixed field, a [:frac, :zero|:nine, digits, separator] tuple for fractional seconds,
          # or nil when no more layout tokens remain (prefix is then the trailing literal).
          # :reek:TooManyStatements
          def self.next_chunk(layout)
            index = 0
            while index < layout.length
              token, length, literal = token_at(layout, index)
              if token
                prefix = layout[0, index + (literal || 0)].to_s
                return [prefix, token, layout[(index + length)..].to_s]
              end

              index += 1
            end
            [layout, nil, ""]
          end

          # The token starting at `i` and its source length, or [nil, 0] if `layout[i]` starts no token.
          def self.token_at(layout, index)
            char = layout[index]
            handler = char && SCANNERS[char]
            handler ? handler.call(layout, index) : [nil, 0]
          end
          private_class_method :token_at

          def self.starts_lower?(rest)
            first = rest && rest[0]
            !first.nil? && first >= "a" && first <= "z"
          end
          private_class_method :starts_lower?

          def self.digit_at?(string, index)
            char = string[index]
            !char.nil? && char >= "0" && char <= "9"
          end
          private_class_method :digit_at?

          # Each scanner returns [token, source_length] for a match at `i`, else [nil, 0].
          # The fixed-field scanners mirror nextStdChunk's per-leading-byte cases.
          # :reek:TooManyStatements
          def self.scan_letter_j(layout, index)
            return [:long_month, 7] if layout[index, 7] == "January"
            return [:month, 3] if layout[index, 3] == "Jan" && !starts_lower?(layout[(index + 3)..])

            [nil, 0]
          end

          # :reek:TooManyStatements
          def self.scan_letter_m(layout, index)
            if layout[index, 3] == "Mon"
              return [:long_weekday, 6] if layout[index, 6] == "Monday"
              return [:weekday, 3] unless starts_lower?(layout[(index + 3)..])
            end
            return [:tz, 3] if layout[index, 3] == "MST"

            [nil, 0]
          end

          ZERO_TOKENS = { "1" => :zero_month, "2" => :zero_day, "3" => :zero_twelve_hour,
                          "4" => :zero_minute, "5" => :zero_second, "6" => :year }.freeze

          def self.scan_zero(layout, index)
            following = layout[index + 1]
            return [ZERO_TOKENS.fetch(following), 2] if following && ZERO_TOKENS.key?(following)
            return [:zero_year_day, 3] if layout[index, 3] == "002"

            [nil, 0]
          end

          def self.scan_one(layout, index)
            return [:hour, 2] if layout[index + 1] == "5"

            [:num_month, 1]
          end

          def self.scan_two(layout, index)
            return [:long_year, 4] if layout[index, 4] == "2006"

            [:day, 1]
          end

          # :reek:TooManyStatements
          def self.scan_underscore(layout, index)
            if layout[index + 1] == "2"
              # "_2006" is a literal underscore followed by the long year (the "_" stays literal).
              return [:long_year, 5, 1] if layout[index, 5] == "_2006"

              return [:under_day, 2]
            end
            return [:under_year_day, 3] if layout[index, 3] == "__2"

            [nil, 0]
          end

          def self.scan_pm_upper(layout, index)
            layout[index + 1] == "M" ? [:pm_upper, 2] : [nil, 0]
          end

          def self.scan_pm_lower(layout, index)
            layout[index + 1] == "m" ? [:pm_lower, 2] : [nil, 0]
          end

          # Numeric (always-signed) zone tokens, longest first.
          NUM_TZ = [["-070000", :num_seconds_tz], ["-07:00:00", :num_colon_seconds_tz],
                    ["-0700", :num_tz], ["-07:00", :num_colon_tz], ["-07", :num_short_tz]].freeze
          # ISO-8601 zone tokens (a "Z" prefix prints Z for UTC), longest first.
          ISO_TZ = [["Z070000", :iso_seconds_tz], ["Z07:00:00", :iso_colon_seconds_tz],
                    ["Z0700", :iso_tz], ["Z07:00", :iso_colon_tz], ["Z07", :iso_short_tz]].freeze

          def self.scan_dash(layout, index)
            scan_table(layout, index, NUM_TZ)
          end

          def self.scan_zed(layout, index)
            scan_table(layout, index, ISO_TZ)
          end

          def self.scan_table(layout, index, table)
            table.each do |text, token|
              return [token, text.length] if layout[index, text.length] == text
            end
            [nil, 0]
          end
          private_class_method :scan_table

          # ".000"/".999"/",000"/",999" — a separator then a run of all-0 or all-9 digits.
          # :reek:TooManyStatements
          def self.scan_fraction(layout, index)
            separator = layout[index]
            digit = layout[index + 1]
            return [nil, 0] unless %w[0 9].include?(digit)

            stop = index + 1
            stop += 1 while layout[stop] == digit
            return [nil, 0] if digit_at?(layout, stop) # the run must end here

            kind = digit == "0" ? :zero : :nine
            [[:frac, kind, stop - (index + 1), separator], stop - index]
          end

          SCANNERS = {
            "J" => method(:scan_letter_j), "M" => method(:scan_letter_m),
            "0" => method(:scan_zero), "1" => method(:scan_one), "2" => method(:scan_two),
            "_" => method(:scan_underscore), "3" => ->(_l, _i) { [:twelve_hour, 1] },
            "4" => ->(_l, _i) { [:minute, 1] }, "5" => ->(_l, _i) { [:second, 1] },
            "P" => method(:scan_pm_upper), "p" => method(:scan_pm_lower),
            "-" => method(:scan_dash), "Z" => method(:scan_zed),
            "." => method(:scan_fraction), "," => method(:scan_fraction)
          }.freeze

          # ISO-8601 zone tokens print "Z" for a zero (UTC) offset; numeric tokens never do.
          ISO_ZONE = %i[iso_tz iso_colon_tz iso_seconds_tz iso_short_tz iso_colon_seconds_tz].freeze
          COLON_ZONE = %i[iso_colon_tz num_colon_tz iso_colon_seconds_tz num_colon_seconds_tz].freeze
          SHORT_ZONE = %i[num_short_tz iso_short_tz].freeze
          SECONDS_ZONE = %i[iso_seconds_tz num_seconds_tz num_colon_seconds_tz iso_colon_seconds_tz].freeze
          COLON_SECONDS_ZONE = %i[num_colon_seconds_tz iso_colon_seconds_tz].freeze
          ZONE_OFFSET = (ISO_ZONE + %i[num_tz num_colon_tz num_seconds_tz num_short_tz num_colon_seconds_tz]).freeze

          # The string for one resolved token (a port of appendFormat's switch). `time` is already in
          # the target zone, so its accessors give the wall-clock fields Go computes from t.locabs().
          # :reek:TooManyStatements
          def self.emit(time, token)
            return emit_fraction(time, token) if token.is_a?(::Array)
            return emit_field(time, token).to_s unless token == :tz || ZONE_OFFSET.include?(token)
            return zone_name(time) if token == :tz

            zone_offset(time, token)
          end
          private_class_method :emit

          # The non-zone fixed fields — a 1:1 port of Go's appendFormat switch, so the long case is
          # the clearest faithful form.
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
          # :reek:TooManyStatements
          def self.emit_field(time, token)
            case token
            when :long_year then pad(time.year, 4)
            when :year then pad(time.year.abs % 100, 2)
            when :month then MONTHS.fetch(time.month - 1)[0, 3]
            when :long_month then MONTHS.fetch(time.month - 1)
            when :num_month then time.month.to_s
            when :zero_month then pad(time.month, 2)
            when :weekday then WEEKDAYS.fetch(time.wday)[0, 3]
            when :long_weekday then WEEKDAYS.fetch(time.wday)
            when :day then time.day.to_s
            when :under_day then time.day.to_s.rjust(2, " ")
            when :zero_day then pad(time.day, 2)
            when :under_year_day then time.yday.to_s.rjust(3, " ")
            when :zero_year_day then pad(time.yday, 3)
            when :hour then pad(time.hour, 2)
            when :twelve_hour then twelve_hour(time.hour).to_s
            when :zero_twelve_hour then pad(twelve_hour(time.hour), 2)
            when :minute then time.min.to_s
            when :zero_minute then pad(time.min, 2)
            when :second then time.sec.to_s
            when :zero_second then pad(time.sec, 2)
            when :pm_upper then time.hour >= 12 ? "PM" : "AM"
            when :pm_lower then time.hour >= 12 ? "pm" : "am"
            end
          end
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
          private_class_method :emit_field

          # Go's stdTZ: the zone abbreviation as-is (Ruby's Time#zone matches Go's name, including
          # the numeric `-05`/`+14`/`+11` IANA abbreviations), falling back to a numeric `-0700` only
          # when no abbreviation is known (an offset-only Time whose zone is empty).
          def self.zone_name(time)
            name = time.zone
            return name if name.is_a?(::String) && !name.empty?

            offset = time.utc_offset
            minutes = offset.abs / 60
            "#{offset.negative? ? "-" : "+"}#{pad(minutes / 60, 2)}#{pad(minutes % 60, 2)}"
          end
          private_class_method :zone_name

          # Go's ISO-8601/numeric offset tokens: ±HH[:]MM[[:]SS], or "Z" for a UTC ISO token.
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
          # :reek:TooManyStatements
          def self.zone_offset(time, token)
            offset = time.utc_offset
            return "Z" if offset.zero? && ISO_ZONE.include?(token)

            absolute = offset.abs
            minutes = absolute / 60
            result = "#{offset.negative? ? "-" : "+"}#{pad(minutes / 60, 2)}"
            result << ":" if COLON_ZONE.include?(token)
            result << pad(minutes % 60, 2) unless SHORT_ZONE.include?(token)
            if SECONDS_ZONE.include?(token)
              result << ":" if COLON_SECONDS_ZONE.include?(token)
              result << pad(absolute % 60, 2)
            end
            result
          end
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
          private_class_method :zone_offset

          # Go's appendNano: the separator + up to `digits` fractional digits; the `:nine` form trims
          # trailing zeros (and the separator itself) and emits nothing when the value rounds to zero.
          # The `digits.zero?` guard mirrors Go's appendNano `n == 0` early return; `scan_fraction`
          # never yields a zero-digit run, so (as in Go) it is a defensively-inert fidelity guard, not
          # reachable dead code.
          # :reek:TooManyStatements
          def self.emit_fraction(time, frac)
            _, kind, digits, separator = frac
            trim = kind == :nine
            return "" if trim && (digits.zero? || time.nsec.zero?)

            result = separator + pad(time.nsec, 9)
            result = result[0, 1 + digits] if digits < 9
            return result unless trim

            result.sub(/0+\z/, "").chomp(separator)
          end
          private_class_method :emit_fraction

          # Zero-pad a non-negative integer to at least `width` digits (Go's appendInt for width > 0).
          def self.pad(value, width)
            value.to_s.rjust(width, "0")
          end
          private_class_method :pad

          # 12-hour clock: noon/midnight are 12.
          def self.twelve_hour(hour)
            twelve = hour % 12
            twelve.zero? ? 12 : twelve
          end
          private_class_method :twelve_hour
        end
        # rubocop:enable Metrics/ModuleLength
      end
    end
  end
end
