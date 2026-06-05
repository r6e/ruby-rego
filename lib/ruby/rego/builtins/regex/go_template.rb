# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in regular-expression helpers (Onigmo engine).
      module Regex
        # Parses a Go `regexp.Expand` replacement template once, then expands it against
        # each match. `$name`/`${name}` reference a submatch (numeric name = numbered
        # group, `$0` = whole match; an unknown or out-of-range reference expands to the
        # empty string), `$$` is a literal `$`, a `$` not followed by a valid name is a
        # literal `$`, and every other character (including backslash) is a literal.
        class GoTemplate
          # Go's Expand reads a name as Unicode letters, digits, and underscore.
          NAME_CHAR = /[\p{L}\p{Nd}_]/

          # Number of parsed segments; the caller charges this per match against the
          # work budget, since each expansion loops exactly this many segments. The
          # template length is capped (MAX_REGEX_SOURCE) before construction, so parse and
          # per-match expand are both O(capped template) — no separate time bound needed.
          attr_reader :segment_count

          # Callers MUST cap the template length (Regex.assert_source_length) before
          # constructing — `parse` materializes `template.chars`, an uninterruptible O(n)
          # call. `replace` is the only caller and does so.
          #
          # @param template [String]
          # @param names [Hash{String => Integer}] named group -> capture index
          def initialize(template, names)
            @names = names
            @segments = parse(template.chars)
            @segment_count = @segments.length
          end

          # Expands the template against `match`, raising once accumulated output would
          # exceed `budget` so a single expansion cannot exhaust memory.
          #
          # @param match [MatchData]
          # @param budget [Integer]
          # @return [String]
          def expand(match, budget)
            out = +""
            @segments.each do |kind, value|
              out << resolve(kind, value, match)
              raise_output_too_large(budget) if out.length > budget
            end
            out
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

          # A purely-numeric name is a numbered group; otherwise a named group. Matching
          # Go's Expand, a multi-digit name with a leading zero (e.g. `01`) is treated as
          # a (typically unknown) named group, not index 1.
          def reference(name)
            numeric_index?(name) ? [:index, name.to_i] : [:name, name]
          end

          # A non-negative integer with no leading zero (Go treats a leading-zero name
          # like `01` as a named, typically unknown, reference rather than index 1).
          def numeric_index?(name)
            name.match?(/\A(?:0|[1-9]\d*)\z/)
          end

          def resolve(kind, value, match)
            case kind
            when :literal then value.to_s
            when :index then match[value.to_i].to_s
            else named_submatch(match, value.to_s)
            end
          end

          # Named references resolve through the capture-index map (the pattern's named
          # groups were rewritten to plain captures). An unknown name expands to empty.
          def named_submatch(match, name)
            index = @names[name]
            index ? match[index].to_s : ""
          end

          def raise_output_too_large(budget)
            raise Ruby::Rego::BuiltinArgumentError.new(
              "regex.replace output exceeds the maximum size",
              expected: "remaining output budget of #{budget} characters",
              actual: "exceeded",
              context: "regex.replace",
              location: nil
            )
          end
        end
      end
    end
  end
end
