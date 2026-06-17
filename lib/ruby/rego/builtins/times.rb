# frozen_string_literal: true

require "time"
require "tzinfo"
require "tzinfo/data" # pin the Ruby (tzinfo-data) timezone database explicitly, not host zoneinfo
require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "times/go_layout"

# rubocop:disable Metrics/ModuleLength
module Ruby
  module Rego
    module Builtins
      # Time parsing builtins (time.parse_rfc3339_ns, time.parse_duration_ns), matching OPA.
      # Both return nanoseconds (an integer); a non-string or an unparseable input is undefined.
      #
      # parse_rfc3339_ns parses a strict RFC 3339 timestamp (uppercase `T`/`Z`, a required zone of
      # `Z` or `±HH:MM`, a fractional second of any length truncated to nanoseconds, a valid
      # calendar date/time) the way Go's time.Parse(time.RFC3339) does, and is undefined when the
      # instant falls outside the int64-nanosecond range (~1677–2262). It lives in times/rfc3339.rb.
      #
      # parse_duration_ns parses a Go duration (signed, fractional, units ns/us/µs/ms/s/m/h, with
      # `0` a valid zero) and OPA's `d`/`w`/`y` extension (rewritten to 24h/168h/8760h, matching
      # OPA's float-through-hours path). The total must fit int64 nanoseconds. It lives in
      # times/duration.rb.
      #
      # date/clock/weekday decompose an instant given as nanoseconds since the Unix epoch — a bare
      # number (interpreted as UTC) or `[ns, tz]` where `tz` is `""`/`"UTC"`, `"Local"`, or an IANA
      # name (resolved via tzinfo). A third array element (a layout, used only by time.format) is
      # accepted and ignored. A non-integer/out-of-int64 ns, a non-string tz, or an unknown zone is
      # undefined.
      #
      # diff (times/diff.rb) returns the calendar difference between two such instants as a
      # non-negative [years, months, days, hours, minutes, seconds] tuple, decomposed in the first
      # operand's zone. add_date (times/arithmetic.rb) adds years/months/days. The duration, rfc3339,
      # diff, and arithmetic clusters reopen this module from sub-files required at the bottom.
      # :reek:TooManyConstants
      module Times
        extend RegistryHelpers

        INT64_MAX = (2**63) - 1
        INT64_MIN = -(2**63)
        NANOS_PER_SECOND = 1_000_000_000

        # Go's Weekday.String() names, indexed by Ruby's Time#wday (Sunday == 0); kept as an
        # explicit table that mirrors Go's spelling rather than deriving the name another way.
        DAY_NAMES = %w[Sunday Monday Tuesday Wednesday Thursday Friday Saturday].freeze

        TIME_FUNCTIONS = {
          "time.parse_rfc3339_ns" => { arity: 1, handler: :parse_rfc3339_ns },
          "time.parse_ns" => { arity: 2, handler: :parse_ns },
          "time.parse_duration_ns" => { arity: 1, handler: :parse_duration_ns },
          "time.date" => { arity: 1, handler: :date },
          "time.clock" => { arity: 1, handler: :clock },
          "time.weekday" => { arity: 1, handler: :weekday },
          "time.diff" => { arity: 2, handler: :diff },
          "time.add_date" => { arity: 4, handler: :add_date },
          "time.format" => { arity: 1, handler: :format }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, TIME_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param value [Ruby::Rego::Value] ns, or [ns, tz] (an optional ignored layout may follow)
        # @return [Array(Integer, Integer, Integer)] [year, month, day]
        def self.date(value)
          time = tz_instant(value, "time.date")
          [time.year, time.month, time.day]
        end

        # @return [Array(Integer, Integer, Integer)] [hour, minute, second]
        def self.clock(value)
          time = tz_instant(value, "time.clock")
          [time.hour, time.min, time.sec]
        end

        # @return [String] the English weekday name
        def self.weekday(value)
          DAY_NAMES.fetch(tz_instant(value, "time.weekday").wday)
        end

        # Formats an instant (ns, [ns, tz], or [ns, tz, layout]) using a Go reference-time layout
        # (default RFC3339Nano; a named constant or a literal layout otherwise), matching OPA.
        # @param value [Ruby::Rego::Value]
        # @return [String, Ruby::Rego::UndefinedValue]
        def self.format(value)
          nanos, zone, layout = operand_parts(value, "time.format")
          GoLayout.format(localize(nanos, zone, "time.format"), layout)
        rescue RangeError
          UndefinedValue.new
        end

        # @return [Integer, nil]
        def self.bounded(nanos)
          nanos if nanos.between?(INT64_MIN, INT64_MAX)
        end
        private_class_method :bounded

        # The instant `nanos` as a Ruby Time decomposed in `zone`.
        def self.localize(nanos, zone, context)
          in_zone(utc_instant(nanos), zone, context)
        end
        private_class_method :localize

        # The instant (a Ruby Time in the requested zone) for a ns / [ns, tz] operand. Raises a
        # BuiltinArgumentError (→ undefined) on a bad number, type, or zone.
        def self.tz_instant(value, context)
          nanos, zone = operand_parts(value, context)
          in_zone(utc_instant(nanos), zone, context)
        rescue RangeError
          # Defensive, consistent with epoch_seconds: a platform whose Time can't represent this
          # instant (e.g. a 32-bit time_t build) is undefined, not a crash. The ns is already
          # int64-bounded, so a 64-bit Time never reaches here.
          raise_time_error(context)
        end
        private_class_method :tz_instant

        # @return [[Integer, String, String]] the nanoseconds, the timezone name, and the layout
        #   (a third array element, used only by time.format — "" when absent). All other callers
        #   destructure just the first two. Any further elements are ignored, matching OPA's tzTime.
        # :reek:TooManyStatements
        def self.operand_parts(value, context)
          return [require_nanos(value, context), "UTC", ""] unless value.is_a?(ArrayValue)

          elements = value.value.to_a
          raise_time_error(context) if elements.empty?
          count = elements.length
          nanos = require_nanos(elements[0], context)
          zone = count > 1 ? require_string(elements[1], context) : "UTC"
          layout = count > 2 ? require_string(elements[2], context) : ""
          [nanos, zone, layout]
        end
        private_class_method :operand_parts

        # The operand as an int64 nanosecond count. OPA converts via big.Float.Int64 and rejects a
        # non-integer or out-of-range value, so a fractional or oversized number is undefined.
        def self.require_nanos(value, context)
          Base.assert_type(value, expected: NumberValue, context: context)
          nanos = integer_value(value.value)
          return nanos if nanos&.between?(INT64_MIN, INT64_MAX)

          raise_time_error(context)
        end
        private_class_method :require_nanos

        # @return [Integer, nil] the number as an integer if it has no fractional part, else nil
        def self.integer_value(number)
          return number if number.is_a?(Integer)
          return nil unless number.is_a?(Float) && number.finite?

          truncated = number.to_i
          number == truncated ? truncated : nil
        end
        private_class_method :integer_value

        def self.require_string(value, context)
          Base.assert_type(value, expected: StringValue, context: context)
          value.value
        end
        private_class_method :require_string

        # The instant `nanos` nanoseconds after the Unix epoch as a UTC Ruby Time.
        def self.utc_instant(nanos)
          ::Time.at(0, nanos, :nanosecond).utc
        end
        private_class_method :utc_instant

        # Converts a UTC time to the requested zone: "" / "UTC" stay UTC, "Local" uses the process's
        # local zone (Go's time.Local), any other name is an IANA identifier resolved via tzinfo.
        def self.in_zone(utc_time, zone, context)
          case zone
          when "", "UTC" then utc_time
          when "Local" then utc_time.getlocal
          else TZInfo::Timezone.get(zone).to_local(utc_time)
          end
        rescue TZInfo::InvalidTimezoneIdentifier, TZInfo::DataSourceNotFound
          # Unknown zone, or (defensively, since tzinfo-data is a dependency) no tz database at all.
          raise_time_error(context)
        end
        private_class_method :in_zone

        def self.raise_time_error(context)
          Base.raise_argument_error("invalid #{context} operand",
                                    expected: "ns or [ns, tz]", actual: "invalid", context: context)
        end
        private_class_method :raise_time_error

        def self.string_arg(value, context)
          Base.assert_type(value, expected: StringValue, context: context)
          value.value
        end
        private_class_method :string_arg
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength

require_relative "times/duration"
require_relative "times/rfc3339"
require_relative "times/parse"
require_relative "times/diff"
require_relative "times/arithmetic"

Ruby::Rego::Builtins::Times.register!
