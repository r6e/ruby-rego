# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in glob helpers.
      module Glob
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
              # `translate` already added each alternative's token sizes to @size; the
              # `+ 1` per alternative (for its `|` joiner) is what makes a brace dominated
              # by empty alternatives (e.g. `{,,,...}`, which add nothing in `translate`)
              # still trip the compile-size guard rather than building an unbounded
              # alternation. The re-added `source.length` is harmless extra conservatism.
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
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity
          def translate_class(pos)
            pos += 1
            negate = @chars[pos] == "!"
            pos += 1 if negate
            elements = [] # @type var elements: Array[[String, bool]]
            while pos < @chars.length && @chars[pos] != "]"
              pos = scan_class_element(elements, pos)
              # Bound the class scan so one enormous class can't build a huge element
              # array before the per-token compile-size guard applies.
              raise_malformed if elements.length > MAX_COMPILED_SIZE
            end
            raise_malformed if pos >= @chars.length || elements.empty?

            ["[#{"^" if negate}#{class_body(elements)}]", pos + 1]
          end
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity

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
