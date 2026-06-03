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
          "regex.find_n" => { arity: 3, handler: :find_n }
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
          Regexp.new(string_arg(pattern_value, "regex.is_valid"))
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
          pattern = string_arg(pattern_value, context)
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
      end
    end
  end
end
# rubocop:enable Naming/PredicatePrefix, Metrics/ModuleLength

Ruby::Rego::Builtins::Regex.register!
