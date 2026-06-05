# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "glob/compiler"

module Ruby
  module Rego
    module Builtins
      # Built-in glob helpers (glob.match, glob.quote_meta). Patterns are compiled to an
      # anchored Ruby Regexp; `*` matches a run of non-delimiter characters, `**` matches
      # across delimiters, `?` matches one non-delimiter character, `[...]`/`[!...]` are
      # character classes, and `{a,b}` is alternation (nesting allowed). Matching is by
      # Unicode codepoint.
      #
      # Delimiters follow OPA: a null argument means "no delimiters" (so `*` matches
      # everything), an empty array defaults to `["."]`, and a non-empty array lists the
      # single-character delimiters.
      #
      # This implements correct glob semantics rather than reproducing known bugs in
      # OPA's matcher (gobwas/glob). Specifically, unlike OPA: character classes use
      # standard semantics — multiple ranges and ranges mixed with literals, e.g.
      # `[A-Za-z]` and `[a0-9]` — instead of gobwas's restrictive single-range grammar
      # (gobwas #47); `?` matches non-ASCII characters consistently by codepoint even
      # mid-pattern, where OPA's `?` still fails on non-ASCII in a sequence (gobwas #41);
      # `?`/`[!...]` require exactly one character rather than also matching the empty
      # string; and the gem yields undefined for degenerate forms that OPA leniently
      # accepts — an unterminated `{a,b`, an empty `{}`, and a trailing or lone backslash.
      # Other malformed patterns (unclosed class, reversed range) yield undefined
      # consistent with OPA. Outside these corrections, well-formed patterns behave
      # identically to OPA.
      #
      # To stay bounded on untrusted input, three caps yield undefined rather than
      # hang/exhaust memory: more than MAX_DELIMITERS delimiters, brace nesting deeper
      # than MAX_BRACE_NESTING, or a compiled source larger than MAX_COMPILED_SIZE.
      module Glob
        extend RegistryHelpers

        GLOB_FUNCTIONS = {
          "glob.match" => { arity: 3, handler: :match },
          "glob.quote_meta" => { arity: 1, handler: :quote_meta }
        }.freeze

        # Metacharacters escaped by glob.quote_meta, matching OPA: the wildcards, class,
        # and brace characters plus the escape character itself. (OPA does not escape the
        # `,` that raw gobwas QuoteMeta does — verified against opa eval.)
        QUOTE_META_PATTERN = /[*?\[\]{}\\]/
        DEFAULT_DELIMITERS = ["."].freeze

        # Upper bound on the delimiter count. The non-delimiter character class is built
        # once from the delimiters, so an enormous delimiter array would do O(n) work
        # before the per-token compile-size guard applies; a count far above any real use
        # is rejected as undefined.
        MAX_DELIMITERS = 1 << 16

        # Per-match timeout (shared knob with the regex builtins) guarding against
        # catastrophic backtracking on an untrusted compiled pattern.
        GLOB_TIMEOUT_SECONDS = ENV.fetch("RUBY_REGO_REGEX_TIMEOUT", "1.0").to_f

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, GLOB_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param pattern [Ruby::Rego::Value]
        # @param delimiters [Ruby::Rego::Value]
        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.match(pattern, delimiters, value)
          pattern_text = string_arg(pattern, "glob.match")
          text = string_arg(value, "glob.match")
          regexp = compile(pattern_text, separators(delimiters))
          BooleanValue.new(regexp.match?(text))
        rescue Regexp::TimeoutError
          raise_glob_error("pattern timed out", pattern_text.to_s)
        end

        # @param pattern [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.quote_meta(pattern)
          text = string_arg(pattern, "glob.quote_meta")
          StringValue.new(text.gsub(QUOTE_META_PATTERN) { |char| "\\#{char}" })
        end

        def self.string_arg(value, context)
          Base.assert_type(value, expected: StringValue, context: context)
          value.value
        end
        private_class_method :string_arg

        # Resolves the delimiter argument: null -> none; empty array -> ["."];
        # otherwise the listed single-character strings.
        # :reek:TooManyStatements
        def self.separators(value)
          return [] if value.is_a?(NullValue)

          Base.assert_type(value, expected: ArrayValue, context: "glob.match delimiters")
          elements = value.value
          count = elements.length
          raise_glob_error("too many delimiters", count.to_s) if count > MAX_DELIMITERS
          chars = elements.map { |element| delimiter_char(element) }
          chars.empty? ? DEFAULT_DELIMITERS : chars
        end
        private_class_method :separators

        def self.delimiter_char(element)
          Base.assert_type(element, expected: StringValue, context: "glob.match delimiter")
          char = element.value
          return char if char.length == 1

          raise_glob_error("delimiter must be a single character", char)
        end
        private_class_method :delimiter_char

        # Compiles a glob pattern into an anchored Ruby Regexp, raising for malformed
        # patterns (which surface as an undefined result).
        def self.compile(pattern, seps)
          source = GlobCompiler.new(pattern, seps).compile
          Regexp.new("\\A#{source}\\z", timeout: GLOB_TIMEOUT_SECONDS)
        rescue RegexpError => e
          raise_glob_error("invalid pattern: #{e.message}", pattern)
        end
        private_class_method :compile

        def self.raise_glob_error(message, actual)
          raise Ruby::Rego::BuiltinArgumentError.new(
            message,
            expected: "valid glob pattern",
            actual: actual,
            context: "glob.match",
            location: nil
          )
        end
        private_class_method :raise_glob_error

      end
    end
  end
end

Ruby::Rego::Builtins::Glob.register!
