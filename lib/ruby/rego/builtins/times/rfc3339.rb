# frozen_string_literal: true

require "time"
require "date"

module Ruby
  module Rego
    module Builtins
      # RFC 3339 parsing for time.parse_rfc3339_ns, ported to match Go's time.Parse(time.RFC3339).
      # Lives apart from the time.* core so that file stays under RubyCritic's complexity budget.
      # Reopens Times; bare references to shared helpers/constants (bounded, NANOS_PER_SECOND,
      # string_arg) resolve via the reopened module's lexical scope.
      module Times
        RFC3339 = /\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})\z/

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
      end
    end
  end
end
