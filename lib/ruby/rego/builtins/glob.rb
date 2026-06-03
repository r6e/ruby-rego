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
      # Malformed patterns (unclosed class/brace, reversed/dangling range, empty `{}`)
      # yield an undefined result.
      #
      # This implements correct glob semantics rather than reproducing known bugs in
      # OPA's matcher (gobwas/glob). Specifically, unlike OPA: character classes may use
      # multiple ranges such as `[A-Za-z]` (gobwas #47); `?` and `[...]` match non-ASCII
      # characters by Unicode codepoint (gobwas #41); and `?`/`[!...]` require exactly one
      # character rather than also matching the empty string. Well-formed ASCII patterns
      # behave identically to OPA.
      module Glob
        extend RegistryHelpers

        GLOB_FUNCTIONS = {
          "glob.match" => { arity: 3, handler: :match },
          "glob.quote_meta" => { arity: 1, handler: :quote_meta }
        }.freeze

        # Glob metacharacters escaped by glob.quote_meta (matching gobwas QuoteMeta).
        QUOTE_META_PATTERN = /[*?\[\]{}]/
        DEFAULT_DELIMITERS = ["."].freeze

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
          chars = value.value.map { |element| delimiter_char(element) }
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

          # @param pattern [String]
          # @param seps [Array[String]] delimiter characters (empty means "no delimiters")
          def initialize(pattern, seps)
            @chars = pattern.chars
            @nonsep = non_delimiter_class(seps)
            @brace_depth = 0
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
              parts << source
            end
            [parts.join, pos]
          end

          # Translates a single glob token at `pos`, returning [source, next_position].
          # :reek:TooManyStatements
          def translate_token(char, pos)
            case char
            when "*" then [star(pos), pos + star_width(pos)]
            when "?" then [@nonsep, pos + 1]
            when "[" then translate_class(pos)
            when "{" then translate_brace(pos)
            when "\\" then escape_literal(pos)
            else [Regexp.escape(char), pos + 1]
            end
          end

          def star(pos)
            @chars[pos + 1] == "*" ? '[\s\S]*' : "#{@nonsep}*"
          end

          def star_width(pos)
            @chars[pos + 1] == "*" ? 2 : 1
          end

          # Translates `\x` into a literal x. A trailing backslash is malformed.
          def escape_literal(pos)
            raise_malformed if pos + 1 >= @chars.length

            [Regexp.escape(@chars[pos + 1]), pos + 2]
          end

          # Translates a `{a,b,...}` group into `(?:a|b|...)`, recursing per alternative.
          # :reek:TooManyStatements
          # rubocop:disable Metrics/MethodLength
          def translate_brace(pos)
            @brace_depth += 1
            raise_malformed if @brace_depth > MAX_BRACE_NESTING
            pos += 1
            alternatives = [] # @type var alternatives: Array[String]
            loop do
              source, pos = translate(pos, top_level: false)
              alternatives << source
              raise_malformed if pos >= @chars.length

              break if @chars[pos] == "}"

              pos += 1 # consume ","
            end
            raise_malformed if alternatives == [""]

            @brace_depth -= 1
            ["(?:#{alternatives.join("|")})", pos + 1]
          end
          # rubocop:enable Metrics/MethodLength

          # Translates `[...]` / `[!...]` into a regex character class.
          # :reek:TooManyStatements
          def translate_class(pos)
            pos += 1
            negate = @chars[pos] == "!"
            pos += 1 if negate
            body = [] # @type var body: Array[String]
            while pos < @chars.length && @chars[pos] != "]"
              body << @chars[pos]
              pos += 1
            end
            raise_malformed if pos >= @chars.length || body.empty?

            ["[#{"^" if negate}#{class_body(body)}]", pos + 1]
          end

          # Converts raw class characters into regex class source, expanding `a-z`
          # ranges and escaping specials. Reversed or dangling ranges are malformed.
          # :reek:TooManyStatements
          # :reek:FeatureEnvy
          # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
          def class_body(chars)
            out = +""
            index = 0
            while index < chars.length
              if chars[index + 1] == "-" && index + 2 < chars.length
                out << class_range(chars[index], chars[index + 2])
                index += 3
              elsif chars[index + 1] == "-"
                raise_malformed # dangling range, e.g. [a-]
              else
                out << escape_in_class(chars[index])
                index += 1
              end
            end
            out
          end
          # rubocop:enable Metrics/AbcSize, Metrics/MethodLength

          def class_range(low, high)
            raise_malformed if low.ord > high.ord

            "#{escape_in_class(low)}-#{escape_in_class(high)}"
          end

          # Escapes a character for use inside a regex character class.
          # :reek:UtilityFunction
          def escape_in_class(char)
            char.gsub(/[\\\]\^\-\[]/) { |meta| "\\#{meta}" }
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
