# frozen_string_literal: true

# rubocop:disable Metrics/AbcSize, Metrics/MethodLength

module Ruby
  module Rego
    module Builtins
      module Regex
        # Tokenizer for the glob-intersection grammar. Lives apart from the
        # intersection core so the main file stays under RubyCritic's complexity
        # budget. Reopens GlobIntersection; Token, GlobError, and the caps live in
        # the main file (loaded first, before this require_relative).
        module GlobIntersection
          # Bounds cumulative character-class range expansion across one glob so a
          # range-packed pattern cannot do unbounded work during tokenization.
          class RuneBudget
            def initialize(limit)
              @remaining = limit
            end

            def charge(count)
              @remaining -= count
              raise GlobError, "character classes expand too many characters" if @remaining.negative?
            end
          end

          def self.tokenize(input)
            chars = input.chars
            tokens = [] # @type var tokens: Array[Token]
            budget = RuneBudget.new(MAX_SET_RUNES)
            index = 0
            while index < chars.length
              token, index = next_token(chars, index, budget)
              tokens << token
            end
            tokens
          end

          def self.next_token(chars, index, budget)
            rune, index, escaped = next_rune(chars, index)
            token, index = atom_token(rune, escaped, chars, index, budget)
            flag, index = next_flag(chars, index)
            token.flag = flag
            [token, index]
          end
          private_class_method :next_token

          def self.atom_token(rune, escaped, chars, index, budget)
            return [Token.new(:char, rune, nil, :none), index] if escaped
            return [Token.new(:dot, nil, nil, :none), index] if rune == "."
            return next_set(chars, index, budget) if rune == "["
            raise GlobError, "set-close ']' with no preceding '['" if rune == "]"
            raise GlobError, "flag '#{rune}' must be preceded by a non-flag" if ["*", "+"].include?(rune)

            [Token.new(:char, rune, nil, :none), index]
          end
          private_class_method :atom_token

          # Reads the rune at +index+, honouring a leading backslash escape.
          # @return [Array(String, Integer, bool)] rune, next index, escaped?
          def self.next_rune(chars, index)
            return [chars[index], index + 1, false] unless chars[index] == "\\"
            raise GlobError, "input ends with a backslash" if index >= chars.length - 1

            [chars[index + 1], index + 2, true]
          end
          private_class_method :next_rune

          # Reads an optional postfix flag at +index+; consumes it only if present.
          # @return [Array(Symbol, Integer)] flag, next index
          def self.next_flag(chars, index)
            return [:none, index] if index >= chars.length
            return [:plus, index + 1] if chars[index] == "+"
            return [:star, index + 1] if chars[index] == "*"

            [:none, index]
          end
          private_class_method :next_flag

          # Parses a `[...]` class starting just after the `[`. Runes are stored as
          # integer codepoints (mirroring gintersect's int32 runes), so a range
          # spanning the UTF-16 surrogate block never reaches String#chr (RangeError).
          # @return [Array(Token, Integer)] set token, next index
          def self.next_set(chars, index, budget)
            runes = Set.new # @type var runes: Set[Integer]
            prev = nil # @type var prev: String?
            while index < chars.length
              rune, index, escaped = next_rune(chars, index)
              if !escaped && rune == "]"
                return [Token.new(:set, nil, runes, :none), index]
              elsif !escaped && rune == "-"
                index = add_range(chars, index, prev, runes, budget)
                prev = nil
              else
                runes << rune.ord
                prev = rune
              end
            end
            raise GlobError, "found '[' without matching ']'"
          end
          private_class_method :next_set

          # Expands a `prev-hi` range (the `-` already consumed) into +runes+ as
          # integer codepoints, charging the cumulative budget first.
          # @return [Integer] next index
          def self.add_range(chars, index, prev, runes, budget)
            raise GlobError, "range '-' must be preceded by a character" unless prev
            raise GlobError, "range '-' must be followed by a character" if index >= chars.length

            hi, index, escaped = next_rune(chars, index)
            raise GlobError, "range '-' cannot be followed by a special symbol" if !escaped && ["]", "-"].include?(hi)
            raise GlobError, "range is out of order" if hi.ord < prev.ord

            budget.charge(hi.ord - prev.ord + 1)
            (prev.ord..hi.ord).each { |codepoint| runes << codepoint }
            index
          end
          private_class_method :add_range
        end
      end
    end
  end
end
# rubocop:enable Metrics/AbcSize, Metrics/MethodLength
