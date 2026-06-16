# frozen_string_literal: true

# rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity

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
        end
      end
    end
  end
end

require_relative "glob_intersection/tokenizer"
require_relative "glob_intersection/trim"
require_relative "glob_intersection/intersector"
# rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
