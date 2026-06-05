# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in regular-expression helpers (Onigmo engine).
      module Regex
        # Replaces every match of `pattern` in `string` with `replacement`, expanding
        # Go's Expand template syntax in the replacement (`$1`/`${name}`/`$$`), matching
        # OPA's `regex.replace`. A backslash is a literal; only `$` is special.
        #
        # @param string_value [Ruby::Rego::Value]
        # @param pattern_value [Ruby::Rego::Value]
        # @param replacement_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.replace(string_value, pattern_value, replacement_value)
          regexp, names = compile_pattern(string_arg(pattern_value, "regex.replace"), "regex.replace")
          string = string_arg(string_value, "regex.replace")
          replacement = string_arg(replacement_value, "regex.replace")
          assert_source_length(replacement, "regex.replace")
          template = GoTemplate.new(replacement, names)
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
        # rubocop:disable Metrics/MethodLength, Metrics/AbcSize
        def self.expand_all(string, regexp, template)
          remaining = MAX_REPLACE_OUTPUT
          work = MAX_REPLACE_WORK
          deadline = match_deadline
          previous_end = -1
          string.gsub(regexp) do |matched|
            # Regexp.last_match is always set inside a gsub block that fired; the guard
            # only narrows the MatchData? type for the type checker.
            match = Regexp.last_match
            next "" if skip_zero_width?(match, previous_end)

            check_deadline(deadline)
            work -= template.segment_count
            raise_replace_work_exceeded if work.negative?
            expansion = match ? template.expand(match, remaining) : matched
            remaining -= expansion.length
            previous_end = match.byteoffset(0).last if match
            expansion
          end
        end
        # rubocop:enable Metrics/MethodLength, Metrics/AbcSize
        private_class_method :expand_all

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
      end
    end
  end
end
