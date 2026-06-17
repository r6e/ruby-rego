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
          end
          # rubocop:enable Naming/PredicateMethod
        end
      end
    end
  end
end
