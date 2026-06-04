# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

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
      # string; and the gem rejects two degenerate brace forms that OPA leniently accepts
      # — an unterminated `{a,b` and an empty `{}` — yielding undefined. Other malformed
      # patterns (unclosed class, reversed range) yield undefined consistent with OPA.
      # Outside these corrections, well-formed patterns behave identically to OPA.
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

        # Translates a glob pattern into a Ruby regex fragment. A fresh instance is used
        # per compile so the scan position is not shared state.
        # rubocop:disable Metrics/ClassLength
        class GlobCompiler
          # Bounds brace-group nesting so a pathological pattern (e.g. deeply nested
          # `{{{...`) cannot exhaust the stack during compilation; exceeding it is treated
          # as a malformed pattern (undefined result).
          MAX_BRACE_NESTING = 100

          # Bounds the generated regex source so a pattern cannot force a super-linear
          # build at compile time. Each `*`/`?` re-emits the (delimiter-sized)
          # non-delimiter class, so a long pattern over many delimiters would otherwise
          # produce an O(pattern x delimiters) source before the match timeout applies.
          MAX_COMPILED_SIZE = 1 << 20

          # @param pattern [String]
          # @param seps [Array[String]] delimiter characters (empty means "no delimiters")
          def initialize(pattern, seps)
            @chars = pattern.chars
            @nonsep = non_delimiter_class(seps)
            @brace_depth = 0
            @size = 0
          end

          # @return [String] regex source (unanchored)
          def compile
            source, pos = translate(0, top_level: true)
            raise_malformed if pos < @chars.length

            source
          end

          private

          # Builds the regex class matching a single non-delimiter character.
          # :reek:FeatureEnvy
          def non_delimiter_class(seps)
            return '[\s\S]' if seps.empty?

            "[^#{seps.map { |sep| escape_in_class(sep) }.join}]"
          end

          # Translates a sequence until end-of-pattern (top level) or until a `,`/`}`
          # that closes the enclosing brace group. Returns [source, position].
          # :reek:TooManyStatements
          def translate(pos, top_level:)
            parts = [] # @type var parts: Array[String]
            while pos < @chars.length
              char = @chars[pos]
              break if !top_level && [",", "}"].include?(char)

              source, pos = translate_token(char, pos)
              @size += source.length
              raise_malformed if @size > MAX_COMPILED_SIZE

              parts << source
            end
            [parts.join, pos]
          end

          # Translates a single glob token at `pos`, returning [source, next_position].
          # :reek:TooManyStatements
          def translate_token(char, pos)
            case char
            when "*" then star(pos)
            when "?" then [@nonsep, pos + 1]
            when "[" then translate_class(pos)
            when "{" then translate_brace(pos)
            when "\\" then escape_literal(pos)
            else [Regexp.escape(char), pos + 1]
            end
          end

          # `**` (superstar) crosses delimiters; a single `*` does not. Returns the
          # regex source and the next position.
          # :reek:FeatureEnvy
          def star(pos)
            return ['[\s\S]*', pos + 2] if @chars[pos + 1] == "*"

            ["#{@nonsep}*", pos + 1]
          end

          # Translates `\x` into a literal x. A trailing backslash is malformed.
          def escape_literal(pos)
            raise_malformed if pos + 1 >= @chars.length

            [Regexp.escape(@chars[pos + 1]), pos + 2]
          end

          # Translates a `{a,b,...}` group into `(?:a|b|...)`, recursing per alternative.
          # :reek:TooManyStatements
          # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
          def translate_brace(pos)
            @brace_depth += 1
            raise_malformed if @brace_depth > MAX_BRACE_NESTING
            pos += 1
            alternatives = [] # @type var alternatives: Array[String]
            loop do
              source, pos = translate(pos, top_level: false)
              alternatives << source
              # Count each alternative (plus its `|`) so a brace dominated by empty
              # alternatives (e.g. `{,,,...}`) still trips the compile-size guard rather
              # than building an unbounded alternation.
              @size += source.length + 1
              raise_malformed if pos >= @chars.length || @size > MAX_COMPILED_SIZE

              break if @chars[pos] == "}"

              pos += 1 # consume ","
            end
            raise_malformed if alternatives == [""]

            @brace_depth -= 1
            ["(?:#{alternatives.join("|")})", pos + 1]
          end
          # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

          # Translates `[...]` / `[!...]` into a regex character class. Scans into
          # [char, escaped?] elements so a backslash escapes the next character (so e.g.
          # `[\]]` is a class matching a literal `]`, not an unterminated class).
          # :reek:TooManyStatements
          def translate_class(pos)
            pos += 1
            negate = @chars[pos] == "!"
            pos += 1 if negate
            elements = [] # @type var elements: Array[[String, bool]]
            pos = scan_class_element(elements, pos) while pos < @chars.length && @chars[pos] != "]"
            raise_malformed if pos >= @chars.length || elements.empty?

            ["[#{"^" if negate}#{class_body(elements)}]", pos + 1]
          end

          # Appends one class element, consuming `\x` as an escaped literal.
          def scan_class_element(elements, pos)
            if @chars[pos] == "\\"
              raise_malformed if pos + 1 >= @chars.length

              elements << [@chars[pos + 1], true]
              return pos + 2
            end
            elements << [@chars[pos], false]
            pos + 1
          end

          # Converts class elements into regex class source. An unescaped `-` between two
          # elements forms an `a-z` range; any other `-` (leading, trailing, or escaped)
          # is a literal character, matching standard glob. A reversed range is malformed.
          # :reek:FeatureEnvy
          # :reek:TooManyStatements
          # rubocop:disable Metrics/MethodLength
          def class_body(elements)
            out = +""
            index = 0
            while index < elements.length
              if range_at?(elements, index)
                out << class_range(elements[index][0], elements[index + 2][0])
                index += 3
              else
                out << escape_in_class(elements[index][0])
                index += 1
              end
            end
            out
          end
          # rubocop:enable Metrics/MethodLength

          # A range occupies three elements: a char, an unescaped `-`, and a high char.
          # :reek:UtilityFunction
          def range_at?(elements, index)
            index + 2 < elements.length && elements[index + 1] == ["-", false]
          end

          def class_range(low, high)
            raise_malformed if low.ord > high.ord

            "#{escape_in_class(low)}-#{escape_in_class(high)}"
          end

          # Escapes a character for use inside a regex character class. `&` is escaped
          # too so `&&` cannot trigger Onigmo character-class intersection.
          # :reek:UtilityFunction
          def escape_in_class(char)
            char.gsub(/[\\\]\^\-\[&]/) { |meta| "\\#{meta}" }
          end

          def raise_malformed
            raise Ruby::Rego::BuiltinArgumentError.new(
              "malformed glob pattern",
              expected: "valid glob pattern",
              actual: @chars.join,
              context: "glob.match",
              location: nil
            )
          end
        end
        # rubocop:enable Metrics/ClassLength
      end
    end
  end
end

Ruby::Rego::Builtins::Glob.register!
