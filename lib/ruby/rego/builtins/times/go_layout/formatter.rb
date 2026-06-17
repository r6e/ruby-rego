# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Times
        # The Go reference-time emitter (a port of appendFormat + appendNano from src/time/format.go).
        # Lives apart from the tokenizer so the go_layout file stays under RubyCritic's complexity
        # budget; reopens the same GoLayout module so bare references to MONTHS/WEEKDAYS and the
        # public surface resolve unchanged.
        module GoLayout
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
      end
    end
  end
end
