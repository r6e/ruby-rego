# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in regular-expression helpers (Onigmo engine).
      module Regex
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

        # Monotonic timestamp REGEX_TIMEOUT_SECONDS in the future, used as an aggregate
        # deadline for a whole match loop (the per-match engine timeout resets each search
        # and so cannot bound a cheap-per-match pattern over a long subject).
        #
        # @return [Float]
        def self.match_deadline
          Process.clock_gettime(Process::CLOCK_MONOTONIC) + REGEX_TIMEOUT_SECONDS
        end
        private_class_method :match_deadline

        # Raises (caught by `guarded` → undefined) once the aggregate deadline has passed.
        # Cheap O(1) cooperative check; safe, unlike thread-based Timeout.
        #
        # @param deadline [Float]
        # @return [void]
        def self.check_deadline(deadline)
          return if Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

          raise Regexp::TimeoutError, "regex evaluation exceeded #{REGEX_TIMEOUT_SECONDS}s"
        end
        private_class_method :check_deadline

        # Yields each successive MatchData, advancing past zero-width matches so the
        # iteration terminates (mirrors String#scan's match positions).
        #
        # @param regexp [Regexp]
        # @param string [String]
        # @yieldparam [MatchData]
        # @return [void]
        # rubocop:disable Metrics/MethodLength
        def self.each_match(regexp, string)
          position = 0
          length = string.length
          previous_end = -1
          deadline = match_deadline
          while position <= length && (found = regexp.match(string, position))
            check_deadline(deadline)
            start = found.begin(0) || 0
            finish = found.end(0) || 0
            yield found unless finish == start && start == previous_end
            previous_end = finish
            position = advance(found)
          end
        end
        # rubocop:enable Metrics/MethodLength
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

        # Like `matches_for`, but each row is the full match followed by its capture
        # groups (a non-participating group yields "", mirroring Go's submatch slice).
        #
        # @return [Array<Array<String>>]
        def self.submatches_for(pattern_value, string_value, context)
          regexp = compile(pattern_value, context)
          string = string_arg(string_value, context)
          guarded(context) { all_submatches(regexp, string) }
        end
        private_class_method :submatches_for

        # @return [Array<Array<String>>]
        def self.all_submatches(regexp, string)
          rows = [] # @type var rows: Array[Array[String]]
          each_match(regexp, string) { |found| rows << submatch_row(found) }
          rows
        end
        private_class_method :all_submatches

        # @param found [MatchData]
        # @return [Array<String>]
        def self.submatch_row(found)
          [found[0] || ""] + found.captures.map { |capture| capture || "" }
        end
        private_class_method :submatch_row
      end
    end
  end
end
