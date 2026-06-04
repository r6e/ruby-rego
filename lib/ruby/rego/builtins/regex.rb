# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "numeric_helpers"

# rubocop:disable Naming/PredicatePrefix, Metrics/ModuleLength
module Ruby
  module Rego
    module Builtins
      # Built-in regex helpers (regex.match, regex.is_valid, regex.split, regex.find_n).
      #
      # Patterns are compiled with Ruby's regex engine (Onigmo), not Go's RE2.
      # Common patterns behave identically to OPA; constructs that Ruby accepts but
      # RE2 rejects (lookahead, backreferences) are treated as valid here.
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
          Regexp.new(translate_named_groups(string_arg(pattern_value, "regex.is_valid")))
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
          regexp = compile(pattern_value, "regex.replace")
          string = string_arg(string_value, "regex.replace")
          template = GoTemplate.new(string_arg(replacement_value, "regex.replace"))
          guarded("regex.replace") do
            StringValue.new(string.gsub(regexp) do |matched|
              match = Regexp.last_match
              match ? template.expand(match) : matched
            end)
          end
        end

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
          value.value
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
          pattern = translate_named_groups(string_arg(pattern_value, context))
          Regexp.new(pattern, timeout: REGEX_TIMEOUT_SECONDS)
        rescue RegexpError => e
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Invalid regular expression: #{e.message}",
            expected: "valid regular expression",
            actual: pattern,
            context: context,
            location: nil
          )
        end
        private_class_method :compile

        # Translates Go's named-group syntax `(?P<name>...)` to Ruby's `(?<name>...)` so
        # OPA patterns with named groups compile (Ruby's Onigmo rejects the `(?P<` form).
        def self.translate_named_groups(pattern)
          pattern.gsub("(?P<", "(?<")
        end
        private_class_method :translate_named_groups

        # Converts a match-timeout (catastrophic backtracking) into an undefined
        # result instead of hanging the evaluator.
        #
        # @param context [String]
        # @return [Ruby::Rego::Value]
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
        end
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
          NAME_CHAR = /[A-Za-z0-9_]/

          # @param template [String]
          def initialize(template)
            @segments = parse(template.chars)
          end

          # @param match [MatchData]
          # @return [String]
          def expand(match)
            @segments.map { |kind, value| resolve(kind, value, match) }.join
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

          # A purely-numeric name is a numbered group; otherwise a named group.
          def reference(name)
            name.match?(/\A\d+\z/) ? [:index, name.to_i] : [:name, name]
          end

          def resolve(kind, value, match)
            case kind
            when :literal then value.to_s
            when :index then match[value.to_i].to_s
            else named_submatch(match, value.to_s)
            end
          end

          # An unknown named group raises IndexError in Ruby; Go expands it to empty.
          def named_submatch(match, name)
            match[name].to_s
          rescue IndexError
            ""
          end
        end
      end
    end
  end
end
# rubocop:enable Naming/PredicatePrefix, Metrics/ModuleLength

Ruby::Rego::Builtins::Regex.register!
