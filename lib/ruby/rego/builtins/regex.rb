# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "numeric_helpers"
require_relative "regex/compilation"
require_relative "regex/matching"
require_relative "regex/go_template"
require_relative "regex/replace"
require_relative "regex/template"
require_relative "regex/glob_intersection"

# rubocop:disable Naming/PredicatePrefix
module Ruby
  module Rego
    module Builtins
      # Built-in regex helpers (regex.match, regex.is_valid, regex.split, regex.find_n,
      # regex.find_all_string_submatch_n, regex.template_match, regex.globs_match,
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
      #
      # Argument-type contract follows OPA: match/split/find_n/replace are partial — a
      # non-string (or invalid-encoding) argument yields undefined — whereas is_valid is
      # total over runtime values, returning false for a non-string, invalid-encoding, or
      # over-length argument and true/false for a valid/invalid pattern string.
      module Regex
        extend RegistryHelpers

        REGEX_FUNCTIONS = {
          "regex.match" => { arity: 2, handler: :match },
          "regex.is_valid" => { arity: 1, handler: :is_valid },
          "regex.split" => { arity: 2, handler: :split },
          "regex.find_n" => { arity: 3, handler: :find_n },
          "regex.find_all_string_submatch_n" => { arity: 3, handler: :find_all_string_submatch_n },
          "regex.template_match" => { arity: 4, handler: :template_match },
          "regex.globs_match" => { arity: 2, handler: :globs_match },
          "regex.replace" => { arity: 3, handler: :replace }
        }.freeze

        # Wall-clock budget for one regex builtin operation. OPA's RE2 engine is linear-time
        # and immune to catastrophic backtracking; Ruby's Onigmo engine is not, so a hostile
        # pattern or input could otherwise hang the evaluator. Applied two ways: as the
        # per-match engine timeout (`Regexp.new(timeout:)`, interrupts a single catastrophic
        # search) and as an aggregate deadline across the match loop (a cheap-per-match
        # pattern over a long subject is O(matches) engine scans, which the per-match timeout
        # — reset each search — does not bound). Either path yields undefined. Override with
        # RUBY_REGO_REGEX_TIMEOUT (seconds).
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

        # Maximum byte length of a pattern or replacement template. Both are split into a
        # character array (`String#chars`) up front — an uninterruptible O(n) C call that no
        # cooperative deadline can bound (the same category as compile cost) — before the
        # per-element processing runs. An oversized source is rejected here by an O(1)
        # bytesize check rather than materialized; the resulting char array then bounds the
        # downstream scan/parse/expand loops, which are all O(source). ~1000x any real
        # pattern or template; exceeding it yields undefined.
        MAX_REGEX_SOURCE = 1_000_000

        # A single RE2 group-name character (`[A-Za-z0-9_]`). Used to scan a `(?P<name>` /
        # `(?<name>` header forward one identifier char at a time, which bounds the scan to
        # the name's length and stops at the first non-identifier — keeping pattern
        # preprocessing linear even for adversarial input like `(?P<` repeated with no `>`.
        GROUP_NAME_CHAR = /[A-Za-z0-9_]/

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
          # OPA's regex.is_valid is total over runtime values: a non-string argument is
          # `false`, not undefined (unlike the other regex built-ins, which type-error to
          # undefined). An over-length pattern is also rejected as not-valid rather than
          # processed (anti-DoS cap; OPA, having no cap, reports a large valid pattern true).
          return BooleanValue.new(false) unless pattern_value.is_a?(StringValue)

          pattern = pattern_value.value
          valid = pattern.valid_encoding? && !source_too_long?(pattern) && compilable?(pattern)
          BooleanValue.new(valid)
        end

        # True when the (translated) pattern compiles. Within-cap only — the caller guards
        # length first, so translate_named_groups cannot raise here.
        #
        # @param pattern [String]
        # @return [Boolean]
        def self.compilable?(pattern)
          Regexp.new(translate_named_groups(pattern, "regex.is_valid").first)
          true
        rescue RegexpError
          false
        end
        private_class_method :compilable?

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

        # @param pattern_value [Ruby::Rego::Value]
        # @param string_value [Ruby::Rego::Value]
        # @param number_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        # :reek:TooManyStatements
        def self.find_all_string_submatch_n(pattern_value, string_value, number_value)
          context = "regex.find_all_string_submatch_n"
          rows = submatches_for(pattern_value, string_value, context)
          limit = NumericHelpers.integer_value(number_value, context: context)
          selected = limit.negative? ? rows : rows.first(limit)
          ArrayValue.new(selected.map { |row| string_array(row) })
        end

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

        # Rejects a pattern or replacement template longer than MAX_REGEX_SOURCE before it is
        # split into a character array (an uninterruptible O(n) C call). O(1) bytesize check
        # (bytesize >= length, so this also bounds the codepoint count); exceeding yields
        # undefined.
        #
        # @param source [String]
        # @param context [String]
        # @return [void]
        def self.assert_source_length(source, context)
          return unless source_too_long?(source)

          raise Ruby::Rego::BuiltinArgumentError.new(
            "Regex source exceeds the maximum length",
            expected: "at most #{MAX_REGEX_SOURCE} bytes",
            actual: "#{source.bytesize} bytes",
            context: context,
            location: nil
          )
        end
        private_class_method :assert_source_length

        # @param source [String]
        # @return [Boolean]
        def self.source_too_long?(source)
          source.bytesize > MAX_REGEX_SOURCE
        end
        private_class_method :source_too_long?

        # @param values [Array<String>]
        # @return [Ruby::Rego::ArrayValue]
        def self.string_array(values)
          ArrayValue.new(values.map { |value| StringValue.new(value) })
        end
        private_class_method :string_array
      end
    end
  end
end
# rubocop:enable Naming/PredicatePrefix

Ruby::Rego::Builtins::Regex.register!
