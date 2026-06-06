# frozen_string_literal: true

# rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/ModuleLength, Metrics/PerceivedComplexity, Naming/PredicateMethod

module Ruby
  module Rego
    module Builtins
      # Built-in regex helpers (regex.globs_match).
      module Regex
        GLOBS_MATCH_CONTEXT = "regex.globs_match"

        # Whether the intersection of two glob patterns matches a non-empty string.
        # An invalid glob (or a DoS-bound breach) yields undefined, matching OPA.
        #
        # @param glob1_value [Ruby::Rego::Value]
        # @param glob2_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.globs_match(glob1_value, glob2_value)
          lhs = string_arg(glob1_value, GLOBS_MATCH_CONTEXT)
          rhs = string_arg(glob2_value, GLOBS_MATCH_CONTEXT)
          BooleanValue.new(GlobIntersection.non_empty?(lhs, rhs))
        rescue GlobIntersection::GlobError => e
          raise_invalid_glob(e.message)
        end

        # @return [void]
        def self.raise_invalid_glob(message)
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Invalid glob for regex.globs_match: #{message}",
            expected: "valid intersectable globs",
            actual: message,
            context: GLOBS_MATCH_CONTEXT,
            location: nil
          )
        end
        private_class_method :raise_invalid_glob

        # Faithful port of github.com/yashtewari/glob-intersection — the library OPA's
        # regex.globs_match delegates to. Decides whether two restricted-regex "globs"
        # share a common non-empty match.
        #
        # Grammar (no alternation or grouping): literal characters; `.` (any single
        # character); `[a-z]` character classes with `-` ranges; `\` escapes any
        # special symbol; and `*`/`+` postfix flags (0+/1+ of the preceding atom).
        #
        # This is bug-for-bug with OPA, including quirks of the algorithm — e.g.
        # `abc.*` vs `abc` is false (intersectNormal exhausts the shorter glob before
        # the trailing `*` token gets its zero-match), and two empty globs are true.
        #
        # DoS bound: gintersect is exponential in the flag count of the smaller glob,
        # and OPA relies on context cancellation it lacks here. Globs exceeding the
        # length or flag caps, or an intersection exceeding the work budget, raise
        # GlobError (surfaced as undefined) rather than running unbounded.
        module GlobIntersection
          # Maximum byte length of a single glob pattern.
          MAX_GLOB_SOURCE = 100_000
          # Maximum number of flags (`*`/`+`) in the smaller-flagged glob; the
          # algorithm is exponential in this count.
          MAX_GLOB_FLAGS = 20
          # Maximum codepoints all character-class ranges in one glob may expand to,
          # cumulatively. Bounds tokenization work, which runs before MAX_WORK applies.
          MAX_SET_RUNES = 1_000_000
          # Maximum number of intersection steps before bailing out.
          MAX_WORK = 5_000_000

          # Raised on invalid glob syntax or a DoS-bound breach; the caller maps it to
          # an undefined result.
          class GlobError < StandardError; end

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

          # A glob atom plus its flag. type ∈ :char/:dot/:set; flag ∈ :none/:plus/:star.
          # rune is set for :char, runes for :set.
          class Token
            attr_accessor :type, :rune, :runes, :flag

            def initialize(type, rune, runes, flag)
              @type = type
              @rune = rune
              @runes = runes
              @flag = flag
            end

            def flagged?
              flag != :none
            end

            # Same atom ignoring flag (used by Simplify).
            def same_atom?(other)
              type == other.type && rune == other.rune && runes == other.runes
            end
          end

          # @return [bool]
          def self.non_empty?(lhs, rhs)
            lhs = new_glob(lhs)
            rhs = new_glob(rhs)
            # Checked before trimming (as gintersect does); trimming only removes
            # unflagged tokens, so the post-trim flag count is never higher.
            ensure_within_flag_limit(lhs, rhs)

            lhs, rhs, prefix_ok = trim_globs(lhs, rhs)
            return false unless prefix_ok

            Intersector.new.intersect_normal(lhs, rhs)
          end

          # @return [Array<Token>]
          def self.new_glob(input)
            raise GlobError, "glob too long" if input.bytesize > MAX_GLOB_SOURCE

            simplify(tokenize(input))
          end

          # --- Tokenizer -------------------------------------------------------

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

          # --- Simplify --------------------------------------------------------

          # Collapses adjacent flagged tokens with the same atom (t+t* == t+, etc.),
          # with FlagPlus taking precedence. Mirrors gintersect's Simplify.
          def self.simplify(tokens)
            return tokens if tokens.empty?

            simple = [tokens.first.dup]
            tokens.drop(1).each do |token|
              latest = simple.last
              if token.flagged? && latest.flagged? && token.same_atom?(latest)
                # FlagPlus wins: t+t* == t+, t*t+ == t+.
                either_plus = token.flag == :plus || latest.flag == :plus
                latest.flag = either_plus ? :plus : :star
              else
                simple << token.dup
              end
            end
            simple
          end
          private_class_method :simplify

          # --- Token matching --------------------------------------------------

          # Whether two atoms (ignoring flags) can match a common character.
          def self.match?(token_lhs, token_rhs)
            type_lhs = token_lhs.type
            type_rhs = token_rhs.type
            return true if type_lhs == :dot || type_rhs == :dot
            return token_lhs.rune == token_rhs.rune if type_lhs == :char && type_rhs == :char
            # Only :char and :set remain; a char's codepoint vs the other's rune set.
            return runes_of(token_rhs).include?(token_lhs.rune.to_s.ord) if type_lhs == :char
            return runes_of(token_lhs).include?(token_rhs.rune.to_s.ord) if type_rhs == :char

            runes_of(token_lhs).intersect?(runes_of(token_rhs))
          end

          # The token's codepoint set (empty for non-set atoms; lets match? stay nil-free).
          def self.runes_of(token)
            token.runes || Set.new
          end
          private_class_method :runes_of

          # --- Trim shared affixes (gintersect.trimGlobs) ----------------------

          def self.trim_globs(lhs, rhs)
            left = trim_prefix(lhs, rhs)
            return [[], [], false] if left.nil?

            suffix = trim_suffix(lhs, rhs, left)
            return [[], [], false] if suffix.nil?

            right_lhs, right_rhs = suffix
            [lhs[left..right_lhs] || [], rhs[left..right_rhs] || [], true]
          end
          private_class_method :trim_globs

          # @return [Integer, nil] index after the trimmed prefix, or nil on mismatch
          def self.trim_prefix(lhs, rhs)
            left = 0
            while left < lhs.length && left < rhs.length && !lhs[left].flagged? && !rhs[left].flagged?
              return nil unless match?(lhs[left], rhs[left])

              left += 1
            end
            # Leave one prefix token untrimmed so neither glob becomes empty.
            left.positive? ? left - 1 : left
          end
          private_class_method :trim_prefix

          # @return [Array(Integer, Integer), nil] last kept indices, or nil on mismatch
          def self.trim_suffix(lhs, rhs, left)
            right_lhs = lhs.length - 1
            right_rhs = rhs.length - 1
            while right_lhs >= 0 && right_lhs >= left && right_rhs >= 0 && right_rhs >= left &&
                  !lhs[right_lhs].flagged? && !rhs[right_rhs].flagged?
              return nil unless match?(lhs[right_lhs], rhs[right_rhs])

              right_lhs -= 1
              right_rhs -= 1
            end
            # Leave one suffix token untrimmed so neither glob becomes empty.
            right_lhs < lhs.length - 1 ? [right_lhs + 1, right_rhs + 1] : [right_lhs, right_rhs]
          end
          private_class_method :trim_suffix

          def self.ensure_within_flag_limit(lhs, rhs)
            flags_lhs = lhs.count(&:flagged?)
            flags_rhs = rhs.count(&:flagged?)
            return if [flags_lhs, flags_rhs].min <= MAX_GLOB_FLAGS

            raise GlobError, "too many flags to intersect"
          end
          private_class_method :ensure_within_flag_limit

          # Recursive intersection engine (gintersect.intersect*). Instance state holds
          # the work budget so the recursion can bail out on pathological input.
          class Intersector
            def initialize
              @work = 0
            end

            # Walks both globs while unflagged tokens match; defers to the special
            # handlers once a flagged token appears.
            def intersect_normal(lhs, rhs)
              index1 = 0
              index2 = 0
              while index1 < lhs.length && index2 < rhs.length
                charge_work
                token_lhs = lhs[index1]
                token_rhs = rhs[index2]
                if token_lhs.flagged? || token_rhs.flagged?
                  return intersect_special(lhs[index1..] || [],
                                           rhs[index2..] || [])
                end
                return false unless GlobIntersection.match?(token_lhs, token_rhs)

                index1 += 1
                index2 += 1
              end
              index1 == lhs.length && index2 == rhs.length
            end

            private

            def charge_work
              @work += 1
              raise GlobError, "intersection too expensive" if @work > MAX_WORK
            end

            # At least one of lhs[0]/rhs[0] is flagged. Both arrays are non-empty:
            # intersect_normal only dispatches here from inside its bounds check.
            def intersect_special(lhs, rhs)
              return dispatch(lhs, rhs) if lhs[0].flagged?

              dispatch(rhs, lhs)
            end

            def dispatch(flagged, other)
              flagged[0].flag == :plus ? intersect_plus(flagged, other) : intersect_star(flagged, other)
            end

            # plussed[0].flag == :plus.
            def intersect_plus(plussed, other)
              return false unless GlobIntersection.match?(plussed[0], other[0])
              # Either plussed[0] gobbles other[0]...
              return true if intersect_star(plussed, other[1..] || [])

              # ...or a flagged other[0] gobbles plussed[0] entirely.
              other[0].flagged? && intersect_normal(plussed[1..] || [], other)
            end

            # starred[0].flag == :star: gobble tokens from other until the remainder
            # intersects starred[1..].
            def intersect_star(starred, other)
              star_token = starred[0]
              next_atom = starred[1]
              other.each_with_index do |token, index|
                charge_work
                if next_atom && GlobIntersection.match?(token, next_atom)
                  return true if intersect_normal(starred[1..] || [], other[index..] || [])
                  return false unless GlobIntersection.match?(token, star_token)
                elsif !GlobIntersection.match?(token, star_token)
                  return false
                end
              end
              next_atom.nil?
            end
          end
        end
      end
    end
  end
end
# rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/ModuleLength, Metrics/PerceivedComplexity, Naming/PredicateMethod
