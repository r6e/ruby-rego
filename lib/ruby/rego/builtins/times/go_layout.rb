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
        # The tokenizer (next_chunk + scan_*) and emitter (emit + appendFormat/appendNano) live in
        # go_layout/scanner.rb and go_layout/formatter.rb, reopening this module.
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
        end
      end
    end
  end
end

require_relative "go_layout/scanner"
require_relative "go_layout/formatter"
