# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Times
        # The Go reference-time tokenizer (a port of nextStdChunk from src/time/format.go).
        # Lives apart from the formatting core so the go_layout file stays under RubyCritic's
        # complexity budget; reopens the same GoLayout module so bare constant references and
        # the public `next_chunk` surface resolve unchanged.
        # rubocop:disable Metrics/ModuleLength
        module GoLayout
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

          # The token at `index` as [token, source_length], or [token, source_length, literal_prefix]
          # when a leading character is literal (the `_2006` case), or [nil, 0] for no token.
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

          # Each scanner returns [token, source_length] for a match at `index` (or a third
          # literal_prefix_length element when a leading char is literal, as in scan_underscore's
          # `_2006`), else [nil, 0]. The fixed-field scanners mirror nextStdChunk's per-leading-byte cases.
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
        end
        # rubocop:enable Metrics/ModuleLength
      end
    end
  end
end
