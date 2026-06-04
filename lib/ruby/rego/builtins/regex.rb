# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "numeric_helpers"

# rubocop:disable Naming/PredicatePrefix, Metrics/ModuleLength
module Ruby
  module Rego
    module Builtins
      # Built-in regex helpers (regex.match, regex.is_valid, regex.split, regex.find_n,
      # regex.replace).
      #
      # Patterns are compiled with Ruby's regex engine (Onigmo), not Go's RE2.
      # Common patterns behave identically to OPA; constructs that Ruby accepts but
      # RE2 rejects (lookahead, backreferences) are treated as valid here. Two engine
      # differences are silent divergences shared by every regex built-in: the `^`/`$`
      # anchors are line anchors in Onigmo but text anchors in RE2 (so on a multi-line
      # subject they match per line here but only at the string ends in OPA), and the
      # `\b`/`\w`/`\d`/`\s` classes are Unicode-aware in Onigmo but ASCII-only in RE2
      # (so they match non-ASCII word characters here but not in OPA).
      module Regex
        extend RegistryHelpers

        REGEX_FUNCTIONS = {
          "regex.match" => { arity: 2, handler: :match },
          "regex.is_valid" => { arity: 1, handler: :is_valid },
          "regex.split" => { arity: 2, handler: :split },
          "regex.find_n" => { arity: 3, handler: :find_n },
          "regex.replace" => { arity: 3, handler: :replace }
        }.freeze

        # Per-match wall-clock budget. OPA's RE2 engine is linear-time and immune to
        # catastrophic backtracking; Ruby's Onigmo engine is not, so a hostile pattern
        # or input could otherwise hang the evaluator. Exceeding the budget yields an
        # undefined result. Override with RUBY_REGO_REGEX_TIMEOUT (seconds).
        REGEX_TIMEOUT_SECONDS = ENV.fetch("RUBY_REGO_REGEX_TIMEOUT", "1.0").to_f

        # Upper bound on `regex.replace` output. The per-match engine timeout does not
        # cover template expansion in the gsub block, so many cheap matches with a large
        # replacement template could otherwise expand output super-linearly (matches x
        # template length). Exceeding this yields undefined — a deliberate anti-DoS
        # divergence from OPA, in the same spirit as the regex timeout above.
        MAX_REPLACE_OUTPUT = 32_000_000

        # Upper bound on total template-segment expansions (matches x template segments).
        # Output size alone is insufficient: references that resolve to empty (an
        # out-of-range `$9` or unknown `${name}`) do CPU work per segment while emitting
        # nothing, so a large template over many matches would otherwise run unbounded
        # under the output cap. Exceeding this yields undefined.
        MAX_REPLACE_WORK = 32_000_000

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, REGEX_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param pattern_value [Ruby::Rego::Value]
        # @param string_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.match(pattern_value, string_value)
          regexp = compile(pattern_value, "regex.match")
          string = string_arg(string_value, "regex.match")
          guarded("regex.match") { BooleanValue.new(regexp.match?(string)) }
        end

        # @param pattern_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.is_valid(pattern_value)
          translated, = translate_named_groups(string_arg(pattern_value, "regex.is_valid"))
          Regexp.new(translated)
          BooleanValue.new(true)
        rescue RegexpError
          BooleanValue.new(false)
        end

        # Splits a string on a pattern, matching Go's regexp.Split (n = -1):
        # leading/trailing empty segments are kept, a zero-width match does not
        # produce a trailing empty segment, and empty input yields [""].
        #
        # @param pattern_value [Ruby::Rego::Value]
        # @param string_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        def self.split(pattern_value, string_value)
          regexp = compile(pattern_value, "regex.split")
          string = string_arg(string_value, "regex.split")
          guarded("regex.split") { string_array(split_segments(regexp, string)) }
        end

        # @param pattern_value [Ruby::Rego::Value]
        # @param string_value [Ruby::Rego::Value]
        # @param number_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        def self.find_n(pattern_value, string_value, number_value)
          matches = matches_for(pattern_value, string_value, "regex.find_n")
          limit = NumericHelpers.integer_value(number_value, context: "regex.find_n")
          string_array(limit.negative? ? matches : matches.first(limit))
        end

        # Replaces every match of `pattern` in `string` with `replacement`, expanding
        # Go's Expand template syntax in the replacement (`$1`/`${name}`/`$$`), matching
        # OPA's `regex.replace`. A backslash is a literal; only `$` is special.
        #
        # @param string_value [Ruby::Rego::Value]
        # @param pattern_value [Ruby::Rego::Value]
        # @param replacement_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.replace(string_value, pattern_value, replacement_value)
          pattern = string_arg(pattern_value, "regex.replace")
          translated, names = translate_named_groups(pattern)
          regexp = compile_source(translated, pattern, "regex.replace")
          string = string_arg(string_value, "regex.replace")
          template = GoTemplate.new(string_arg(replacement_value, "regex.replace"), names)
          guarded("regex.replace") { StringValue.new(expand_all(string, regexp, template)) }
        end

        # Replaces every match with its expanded template via gsub (a single linear scan),
        # but applies Go/RE2's match rule: a zero-width match immediately after a non-empty
        # one is skipped (Ruby's gsub would otherwise emit it). Two budgets are threaded
        # through the loop: `remaining` bounds total output characters, and `work` bounds
        # total template-segment expansions (matches x segments) so references that resolve
        # to empty — doing CPU work while emitting nothing — cannot run unbounded under the
        # output cap alone.
        # :reek:TooManyStatements
        # rubocop:disable Metrics/MethodLength
        def self.expand_all(string, regexp, template)
          remaining = MAX_REPLACE_OUTPUT
          work = MAX_REPLACE_WORK
          previous_end = -1
          string.gsub(regexp) do |matched|
            # Regexp.last_match is always set inside a gsub block that fired; the guard
            # only narrows the MatchData? type for the type checker.
            match = Regexp.last_match
            next "" if skip_zero_width?(match, previous_end)

            work -= template.segment_count
            raise_replace_work_exceeded if work.negative?
            expansion = match ? template.expand(match, remaining) : matched
            remaining -= expansion.length
            previous_end = match.byteoffset(0).last if match
            expansion
          end
        end
        # rubocop:enable Metrics/MethodLength
        private_class_method :expand_all

        # The work-budget counterpart to GoTemplate's output cap: raised when the total
        # number of template-segment expansions exceeds MAX_REPLACE_WORK, yielding an
        # undefined result. Deliberate anti-DoS divergence from OPA.
        def self.raise_replace_work_exceeded
          raise Ruby::Rego::BuiltinArgumentError.new(
            "regex.replace exceeds the maximum work budget",
            expected: "at most #{MAX_REPLACE_WORK} template-segment expansions",
            actual: "exceeded",
            context: "regex.replace",
            location: nil
          )
        end
        private_class_method :raise_replace_work_exceeded

        # Go/RE2 drops a zero-width match that begins exactly where the previous match
        # ended; Ruby's gsub keeps it. Byte offsets are used (O(1)); character offsets
        # (begin/end) would cost O(position) per match, making a long zero-width scan
        # quadratic.
        def self.skip_zero_width?(match, previous_end)
          return false unless match

          start, finish = match.byteoffset(0)
          finish == start && start == previous_end
        end
        private_class_method :skip_zero_width?

        # Compiles, validates, and runs an all-matches scan under the timeout guard.
        #
        # @param pattern_value [Ruby::Rego::Value]
        # @param string_value [Ruby::Rego::Value]
        # @param context [String]
        # @return [Array<String>]
        def self.matches_for(pattern_value, string_value, context)
          regexp = compile(pattern_value, context)
          string = string_arg(string_value, context)
          guarded(context) { full_matches(regexp, string) }
        end
        private_class_method :matches_for

        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [String]
        def self.string_arg(value, context)
          Base.assert_type(value, expected: StringValue, context: context)
          string = value.value
          return string if string.valid_encoding?

          # Matching on an invalid-encoding string raises rather than returning a clean
          # result. OPA never sees these (JSON input is valid UTF-8); they reach the
          # public Ruby API only. Until string encoding is normalised at the value-
          # ingestion boundary (a deferred refactor noted in TODO.md), reject them here.
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Invalid string encoding",
            expected: "valid #{string.encoding} string",
            actual: "invalid byte sequence",
            context: context,
            location: nil
          )
        end
        private_class_method :string_arg

        # @param values [Array<String>]
        # @return [Ruby::Rego::ArrayValue]
        def self.string_array(values)
          ArrayValue.new(values.map { |value| StringValue.new(value) })
        end
        private_class_method :string_array

        # @param pattern_value [Ruby::Rego::Value]
        # @param context [String]
        # @return [Regexp]
        def self.compile(pattern_value, context)
          pattern = string_arg(pattern_value, context)
          translated, = translate_named_groups(pattern)
          compile_source(translated, pattern, context)
        end
        private_class_method :compile

        # Compiles an already-translated pattern source, reporting the original pattern
        # on failure.
        def self.compile_source(source, original, context)
          Regexp.new(source, timeout: REGEX_TIMEOUT_SECONDS)
        rescue RegexpError => e
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Invalid regular expression: #{e.message}",
            expected: "valid regular expression",
            actual: original,
            context: context,
            location: nil
          )
        end
        private_class_method :compile_source

        # Rewrites Go's named groups `(?P<name>...)` to plain capturing groups `(...)` and
        # returns [translated_pattern, name_to_index]. RE2 numbers named and unnamed groups
        # in one left-to-right space and resolves `${name}` references through it, so the
        # pattern keeps plain captures (Ruby's engine renumbers if it sees a named group)
        # and named references resolve through the returned index map. A name must be an
        # RE2 identifier (`[A-Za-z0-9_]+`); a Unicode name is left untranslated so the
        # `(?P<` form fails to compile (yielding undefined), matching RE2. An escaped
        # `\(?P<` or one inside a character class is left untouched.
        # :reek:TooManyStatements
        # :reek:DuplicateMethodCall
        # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
        def self.translate_named_groups(pattern)
          out = +""
          names = {} # @type var names: Hash[String, Integer]
          chars = pattern.chars
          pos = 0
          in_class = false
          group_index = 0
          while pos < chars.length
            char = chars[pos]
            if char == "\\"
              out << char << chars[pos + 1].to_s
              pos += 2
            elsif in_class
              in_class = false if char == "]"
              out << char
              pos += 1
            elsif (name = named_group_at(chars, pos))
              group_index += 1
              # A duplicate name resolves to its first occurrence (matching OPA/RE2).
              names[name] ||= group_index
              out << "("
              pos += 5 + name.length
            else
              in_class = true if char == "["
              group_index += 1 if char == "(" && chars[pos + 1] != "?"
              out << char
              pos += 1
            end
          end
          [out, names]
        end
        # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
        private_class_method :translate_named_groups

        # If `chars` at `pos` opens a `(?P<name>` group with an RE2-identifier name,
        # returns the name; otherwise nil (so the position is handled literally).
        # :reek:TooManyStatements
        def self.named_group_at(chars, pos)
          return nil unless chars[pos, 4] == ["(", "?", "P", "<"]

          name_start = pos + 4
          relative_end = chars[name_start..]&.index(">")
          return nil unless relative_end&.positive?

          name = chars[name_start, relative_end].to_a.join
          name.match?(/\A[A-Za-z0-9_]+\z/) ? name : nil
        end
        private_class_method :named_group_at

        # Converts a match-timeout (catastrophic backtracking) into an undefined
        # result instead of hanging the evaluator.
        #
        # @param context [String]
        # @return [Ruby::Rego::Value]
        # rubocop:disable Metrics/MethodLength
        def self.guarded(context)
          yield
        rescue Regexp::TimeoutError
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Regex evaluation timed out",
            expected: "completion within #{REGEX_TIMEOUT_SECONDS}s",
            actual: "timeout",
            context: context,
            location: nil
          )
        rescue EncodingError => e
          # Incompatible pattern/subject encodings surface here as an undefined result.
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Regex encoding error: #{e.message}",
            expected: "compatible string encodings",
            actual: e.class.name,
            context: context,
            location: nil
          )
        end
        # rubocop:enable Metrics/MethodLength
        private_class_method :guarded

        # Yields each successive MatchData, advancing past zero-width matches so the
        # iteration terminates (mirrors String#scan's match positions).
        #
        # @param regexp [Regexp]
        # @param string [String]
        # @yieldparam [MatchData]
        # @return [void]
        def self.each_match(regexp, string)
          position = 0
          length = string.length
          previous_end = -1
          while position <= length && (found = regexp.match(string, position))
            start = found.begin(0) || 0
            finish = found.end(0) || 0
            yield found unless finish == start && start == previous_end
            previous_end = finish
            position = advance(found)
          end
        end
        private_class_method :each_match

        # @param found [MatchData]
        # @return [Integer]
        def self.advance(found)
          finish = found.end(0) || 0
          finish > (found.begin(0) || 0) ? finish : finish + 1
        end
        private_class_method :advance

        # @param regexp [Regexp]
        # @param string [String]
        # @return [Array<String>]
        def self.full_matches(regexp, string)
          matches = [] # @type var matches: Array[String]
          each_match(regexp, string) { |found| matches << (found[0] || "") }
          matches
        end
        private_class_method :full_matches

        # Port of Go's regexp.Split with n = -1. The branchiness (skip the empty
        # segment before a zero-width match at index 0; omit the trailing segment
        # when the final match ends the string) mirrors Go's algorithm directly.
        #
        # @param regexp [Regexp]
        # @param string [String]
        # @return [Array<String>]
        # rubocop:disable Metrics/CyclomaticComplexity, Metrics/MethodLength
        def self.split_segments(regexp, string)
          return [""] if string.empty?

          segments = [] # @type var segments: Array[String]
          cursor = 0
          final_start = 0
          each_match(regexp, string) do |found|
            start = found.begin(0) || 0
            finish = found.end(0) || 0
            final_start = start
            segments << (string[cursor...start] || "") unless finish.zero?
            cursor = finish
          end
          segments << (string[cursor..] || "") unless final_start == string.length
          segments
        end
        # rubocop:enable Metrics/CyclomaticComplexity, Metrics/MethodLength
        private_class_method :split_segments

        # Parses a Go `regexp.Expand` replacement template once, then expands it against
        # each match. `$name`/`${name}` reference a submatch (numeric name = numbered
        # group, `$0` = whole match; an unknown or out-of-range reference expands to the
        # empty string), `$$` is a literal `$`, a `$` not followed by a valid name is a
        # literal `$`, and every other character (including backslash) is a literal.
        class GoTemplate
          # Go's Expand reads a name as Unicode letters, digits, and underscore.
          NAME_CHAR = /[\p{L}\p{Nd}_]/

          # Number of parsed segments; the caller charges this per match against the
          # work budget, since each expansion loops exactly this many segments.
          attr_reader :segment_count

          # @param template [String]
          # @param names [Hash{String => Integer}] named group -> capture index
          def initialize(template, names)
            @names = names
            @segments = parse(template.chars)
            @segment_count = @segments.length
          end

          # Expands the template against `match`, raising once accumulated output would
          # exceed `budget` so a single expansion cannot exhaust memory.
          #
          # @param match [MatchData]
          # @param budget [Integer]
          # @return [String]
          def expand(match, budget)
            out = +""
            @segments.each do |kind, value|
              out << resolve(kind, value, match)
              raise_output_too_large(budget) if out.length > budget
            end
            out
          end

          private

          # Returns [[kind, value], ...] where kind is :literal, :index, or :name.
          # :reek:TooManyStatements
          # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
          def parse(chars)
            segments = [] # @type var segments: Array[[Symbol, String | Integer]]
            literal = +""
            pos = 0
            while pos < chars.length
              if chars[pos] != "$"
                literal << chars[pos]
                pos += 1
                next
              end
              if chars[pos + 1] == "$"
                literal << "$"
                pos += 2
                next
              end
              name, next_pos = extract(chars, pos)
              if name.nil?
                literal << "$"
                pos += 1
                next
              end
              unless literal.empty?
                segments << [:literal, literal]
                literal = +""
              end
              segments << reference(name)
              pos = next_pos
            end
            segments << [:literal, literal] unless literal.empty?
            segments
          end
          # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

          # Extracts a `$name`/`${name}` reference name starting at the `$` in `chars`.
          # Returns [name, next_pos], or [nil, _] when the `$` is not a valid reference.
          # :reek:TooManyStatements
          def extract(chars, pos)
            cursor = pos + 1
            braced = chars[cursor] == "{"
            cursor += 1 if braced
            start = cursor
            cursor += 1 while NAME_CHAR.match?(chars[cursor])
            name = chars[start...cursor].to_a.join
            return [nil, pos] if name.empty?
            return [nil, pos] if braced && chars[cursor] != "}"

            [name, braced ? cursor + 1 : cursor]
          end

          # A purely-numeric name is a numbered group; otherwise a named group. Matching
          # Go's Expand, a multi-digit name with a leading zero (e.g. `01`) is treated as
          # a (typically unknown) named group, not index 1.
          def reference(name)
            numeric_index?(name) ? [:index, name.to_i] : [:name, name]
          end

          def numeric_index?(name)
            name.match?(/\A\d+\z/) && !(name.length > 1 && name.start_with?("0"))
          end

          def resolve(kind, value, match)
            case kind
            when :literal then value.to_s
            when :index then match[value.to_i].to_s
            else named_submatch(match, value.to_s)
            end
          end

          # Named references resolve through the capture-index map (the pattern's named
          # groups were rewritten to plain captures). An unknown name expands to empty.
          def named_submatch(match, name)
            index = @names[name]
            index ? match[index].to_s : ""
          end

          def raise_output_too_large(budget)
            raise Ruby::Rego::BuiltinArgumentError.new(
              "regex.replace output exceeds the maximum size",
              expected: "remaining output budget of #{budget} characters",
              actual: "exceeded",
              context: "regex.replace",
              location: nil
            )
          end
        end
      end
    end
  end
end
# rubocop:enable Naming/PredicatePrefix, Metrics/ModuleLength

Ruby::Rego::Builtins::Regex.register!
