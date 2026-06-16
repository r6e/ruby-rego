# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Yaml
        # Port of gopkg.in/yaml.v2's keyList natural ordering: digit runs compare
        # numerically (so "item2" < "item10"), letters lexicographically, and a digit
        # sorts before a letter. OPA's map keys are strings post-JSON, so only that
        # path applies. Lives apart from the node-building core so the emitter file
        # stays under RubyCritic's complexity budget.
        module Emitter
          # Port of gopkg.in/yaml.v2's keyList.Less (v2.4.0) string path — OPA's keys are
          # strings post-JSON, so only that branch applies. Digit runs compare numerically,
          # letters lexicographically, and a digit sorts before a letter.
          # @return [Integer] -1, 0, or 1
          def self.natural_compare(left, right)
            lhs = left.chars
            rhs = right.chars
            index = 0
            while index < lhs.length && index < rhs.length
              return compare_at(lhs, rhs, index) unless lhs[index] == rhs[index]

              index += 1
            end
            lhs.length <=> rhs.length
          end
          private_class_method :natural_compare

          # Compares the two key strings at their first differing rune (index).
          # @return [Integer]
          def self.compare_at(lhs, rhs, index)
            left_alpha = letter?(lhs[index])
            right_alpha = letter?(rhs[index])
            return lhs[index] <=> rhs[index] if left_alpha && right_alpha
            return left_alpha ? 1 : -1 if left_alpha || right_alpha

            compare_digit_runs(lhs, rhs, index)
          end
          private_class_method :compare_at

          # Both differing runes are digits: compare the whole runs numerically, then by
          # length (leading zeros), then by rune — mirroring keyList.Less.
          # @return [Integer]
          def self.compare_digit_runs(lhs, rhs, index)
            bias = leading_zero_bias(lhs, rhs, index)
            left_value, left_end = digit_run(lhs, index, bias)
            right_value, right_end = digit_run(rhs, index, bias)
            return left_value <=> right_value unless left_value == right_value
            return left_end <=> right_end unless left_end == right_end

            lhs[index] <=> rhs[index]
          end
          private_class_method :compare_digit_runs

          # @return [Array(Integer, Integer)] numeric value of the run (offset by bias) and its end index
          # NOTE: Ruby integers are arbitrary precision, so a >= 2^63 digit run sorts
          # numerically; yaml.v2's int64 accumulator wraps there, so OPA can order such
          # huge-numeric keys differently. Documented divergence (correct over bug-for-bug).
          def self.digit_run(chars, index, bias)
            value = bias
            cursor = index
            while cursor < chars.length && digit?(chars[cursor])
              value = (value * 10) + chars[cursor].to_i
              cursor += 1
            end
            [value, cursor]
          end
          private_class_method :digit_run

          # keyList's leading-zero tie-break: if a non-zero digit precedes the run in the
          # left key, both run values start at 1 so a shorter (fewer-leading-zero) run wins.
          # @return [Integer]
          def self.leading_zero_bias(lhs, rhs, index)
            return 0 unless lhs[index] == "0" || rhs[index] == "0"

            position = index - 1
            while position >= 0 && digit?(lhs[position])
              return 1 unless lhs[position] == "0"

              position -= 1
            end
            0
          end
          private_class_method :leading_zero_bias

          # ASCII-only: non-ASCII decimal digits can't reach here via OPA's JSON-stringified keys.
          # @return [bool]
          def self.digit?(char)
            char.between?("0", "9")
          end
          private_class_method :digit?

          # @return [bool]
          def self.letter?(char)
            char.match?(/\p{L}/)
          end
          private_class_method :letter?
        end
      end
    end
  end
end
