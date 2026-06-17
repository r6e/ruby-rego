# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Times
        module GoLayout
          # The timezone-parsing half of the parser: numeric/ISO offsets (`-0700`, `Z07:00`) and
          # named abbreviations (`MST`, `GMT…`) per Go's parseTimeZone grammar. Split from the
          # driver so parser.rb stays under RubyCritic's complexity budget; the class path is
          # unchanged, so ZONE_SHAPES and the broken-down fields resolve as before.
          # rubocop:disable Naming/PredicateMethod -- the consume_* helpers return a success
          # boolean for control flow (false aborts the parse); they are not predicates.
          # :reek:InstanceVariableAssumption -- @value/@zone_offset are set in Parser#initialize
          # (parser.rb); this reopen only reads/updates those already-established fields.
          class Parser
            private

            # A numeric (`-0700`) or ISO (`Z07:00`) zone offset. ISO tokens accept a bare `Z`
            # for UTC; otherwise a sign and the shape's digit groups give a signed offset.
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

            # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
            def apply_offset(text, shape)
              hh = two_digits(text, shape[:hh]) || (return false)
              mm = shape[:mm] ? (two_digits(text, shape[:mm]) || (return false)) : 0
              ss = shape[:ss] ? (two_digits(text, shape[:ss]) || (return false)) : 0
              # Go's time.Parse range-checks each field independently: an hour up to 24 and a
              # minute/second up to 60 are accepted (so `+24:60` is valid), but `+25:00`/`+12:61`
              # are not. Mirrors RFC3339 (times/rfc3339.rb#zone_offset).
              return false if hh > 24 || mm > 60 || ss > 60

              magnitude = (hh * 3600) + (mm * 60) + ss
              offset = text[0] == "-" ? -magnitude : magnitude
              # Go's parse uses zoneOffset == -1 as the "no zone seen" sentinel, so an explicit
              # offset of exactly -1 second (only reachable as `-00:00:01`) collides with it and is
              # never applied — the instant keeps its naive value. Map it to 0 to match OPA.
              @zone_offset = offset == -1 ? 0 : offset
              @value = @value[shape[:len]..]
              true
            end
            # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

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
            # specials; a leading `+`/`-` is an unnamed signed-offset zone (consumed for its
            # length only — the offset stays 0, like every abbreviation); otherwise a run of 3
            # (always), or 4/5 ending in `T` (plus WITA), uppercase letters.
            # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/AbcSize, Metrics/MethodLength
            def named_zone_length(value)
              return 0 if value.length < 3
              return 4 if %w[ChST MeST].include?(value[0, 4])
              return gmt_length(value) if value[0, 3] == "GMT"
              return signed_offset_length(value) if %w[+ -].include?(value[0])

              upper = uppercase_run(value)
              case upper
              when 3 then 3
              when 4 then value[3] == "T" || value[0, 4] == "WITA" ? 4 : 0
              when 5 then value[4] == "T" ? 5 : 0
              else 0
              end
            end
            # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/AbcSize, Metrics/MethodLength

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

            # Length of a `+`/`-` sign plus its leading integer, or 0 when no digit follows the
            # sign or the integer exceeds 23 — Go's parseSignedOffset returns 0 in both cases, so
            # the sign is NOT consumed (it becomes leftover text and the parse fails).
            def signed_offset_length(rest)
              digits = rest[1..].to_s[/\A\d+/]
              return 0 if digits.nil? || digits.to_i > 23

              1 + digits.length
            end

            # Read exactly two digits at `index`, or nil if either is not a digit.
            def two_digits(text, index)
              return nil unless digit?(text[index]) && digit?(text[index + 1])

              text[index, 2].to_i
            end
          end
          # rubocop:enable Naming/PredicateMethod
        end
      end
    end
  end
end
