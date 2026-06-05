# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in regular-expression helpers (Onigmo engine).
      module Regex
        # @param pattern_value [Ruby::Rego::Value]
        # @param context [String]
        # @return [Regexp]
        def self.compile(pattern_value, context)
          compile_pattern(string_arg(pattern_value, context), context).first
        end
        private_class_method :compile

        # Translates Go named groups and compiles the result, returning the compiled
        # Regexp together with the named-group index map (empty when there are none).
        #
        # @param pattern [String] the original (untranslated) pattern source
        # @param context [String]
        # @return [[Regexp, Hash{String => Integer}]]
        def self.compile_pattern(pattern, context)
          translated, names = translate_named_groups(pattern, context)
          [compile_source(translated, pattern, context), names]
        end
        private_class_method :compile_pattern

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
        def self.translate_named_groups(pattern, context)
          assert_source_length(pattern, context)
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
            elsif (named = named_group_at(chars, pos))
              name, consumed = named
              group_index += 1
              # A duplicate name resolves to its first occurrence (matching OPA/RE2).
              names[name] ||= group_index
              out << "("
              pos += consumed
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

        # If `chars` at `pos` opens a named group — RE2 accepts both `(?P<name>` and the
        # synonym `(?<name>` — returns `[name, consumed]` (consumed = full header length
        # through the `>`); otherwise nil (the position is handled literally). The name is
        # scanned forward one `[A-Za-z0-9_]` character at a time and must be terminated by
        # `>`; this enforces the RE2-identifier rule and keeps the scan O(name length) — a
        # non-identifier first char stops it at once, so a pattern of many `(?P<` with no
        # `>` stays linear, and lookbehind `(?<=`/`(?<!` (first char `=`/`!`) and empty
        # `(?<>` fall through to nil (left untranslated; OPA rejects them too).
        # :reek:TooManyStatements
        # :reek:DuplicateMethodCall
        def self.named_group_at(chars, pos)
          name_start = named_group_name_start(chars, pos)
          return nil unless name_start

          cursor = name_start
          cursor += 1 while GROUP_NAME_CHAR.match?(chars[cursor])
          return nil unless cursor > name_start && chars[cursor] == ">"

          [chars[name_start, cursor - name_start].to_a.join, cursor - pos + 1]
        end
        private_class_method :named_group_at

        # Offset of the name within a `(?P<name>` (4) or `(?<name>` (3) header at `pos`,
        # or nil when `pos` does not open a named group.
        def self.named_group_name_start(chars, pos)
          header = chars[pos, 4]
          return nil unless header
          return pos + 4 if header == ["(", "?", "P", "<"]

          header[0, 3] == ["(", "?", "<"] ? pos + 3 : nil
        end
        private_class_method :named_group_name_start
      end
    end
  end
end
