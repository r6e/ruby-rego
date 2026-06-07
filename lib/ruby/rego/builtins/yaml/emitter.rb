# frozen_string_literal: true

# rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/ModuleLength

require "psych"

module Ruby
  module Rego
    module Builtins
      module Yaml
        # Builds a Psych node tree and emits it, matching OPA's yaml.marshal byte-for-byte.
        #
        # Layout, folding, escaping, and the plain→single/double downgrade are delegated
        # to Psych (libyaml — the engine gopkg.in/yaml.v2 ports), so they match for free.
        # This module supplies only what diverges from Psych's defaults: object keys are
        # sorted, floats use Go's strconv 'g' (shortest, eprec=6) formatting, nil emits as
        # `null`, and scalar styles are set explicitly (DOUBLE for type-ambiguous strings).
        module Emitter
          # Raised when a value cannot be marshaled (e.g. a non-finite number).
          class MarshalError < StandardError; end

          PLAIN = Psych::Nodes::Scalar::PLAIN
          DOUBLE = Psych::Nodes::Scalar::DOUBLE_QUOTED
          LITERAL = Psych::Nodes::Scalar::LITERAL
          # ANY lets libyaml auto-pick plain/single/double exactly as yaml.v2's libyaml
          # does — so the structural quote choice matches OPA for free.
          AUTO = Psych::Nodes::Scalar::ANY
          BLOCK_SEQ = Psych::Nodes::Sequence::BLOCK
          BLOCK_MAP = Psych::Nodes::Mapping::BLOCK

          # yaml.v2 quotes strings that would otherwise resolve to a timestamp or a
          # base-60 number (the latter dropped from resolution but still quoted out).
          TIMESTAMP = /\A\d{4}-\d{1,2}-\d{1,2}([Tt ]\d{1,2}:\d{1,2}:\d{1,2}(\.\d+)?([Zz]|[+-]\d{1,2}(:\d{2})?)?)?\z/
          BASE60 = /\A[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9_]*)?\z/

          # @param ruby [Object] a JSON-compatible Ruby value
          # @return [String]
          def self.emit(ruby)
            document = Psych::Nodes::Document.new([], [], true)
            document.implicit_end = true
            document.children << build_node(ruby)
            stream = Psych::Nodes::Stream.new
            stream.children << document
            stream.to_yaml
          rescue Psych::Exception => e
            raise MarshalError, e.message
          end

          # @return [Psych::Nodes::Node]
          # :reek:TooManyStatements
          def self.build_node(ruby)
            case ruby
            when nil then scalar("null", PLAIN)
            when true then scalar("true", PLAIN)
            when false then scalar("false", PLAIN)
            when Integer then scalar(ruby.to_s, PLAIN)
            when Float then scalar(float_string(ruby), PLAIN)
            when String then string_scalar(ruby)
            when Symbol then string_scalar(ruby.to_s)
            when Array then sequence(ruby)
            when Set then sequence(sorted_set(ruby))
            when Hash then mapping(ruby)
            else raise MarshalError, "unsupported type #{ruby.class}"
            end
          end
          private_class_method :build_node

          # Emits a string scalar, first replacing invalid UTF-8 with U+FFFD (as OPA's
          # JSON round-trip does) so libyaml never rejects the bytes.
          # @return [Psych::Nodes::Scalar]
          def self.string_scalar(string)
            clean = sanitize(string)
            scalar(clean, string_style(clean))
          end
          private_class_method :string_scalar

          # @return [String]
          def self.sanitize(string)
            return string if string.encoding == Encoding::UTF_8 && string.valid_encoding?

            string.dup.force_encoding(Encoding::UTF_8).scrub("�")
          end
          private_class_method :sanitize

          # Builds a scalar node. PLAIN/DOUBLE force that style; AUTO sets both implicit
          # flags so libyaml picks plain/single/double/literal itself (no `!` tag).
          # @return [Psych::Nodes::Scalar]
          def self.scalar(value, style)
            case style
            when PLAIN then Psych::Nodes::Scalar.new(value, nil, nil, true, false, PLAIN)
            when DOUBLE then Psych::Nodes::Scalar.new(value, nil, nil, false, true, DOUBLE)
            when LITERAL then Psych::Nodes::Scalar.new(value, nil, nil, false, true, LITERAL)
            else Psych::Nodes::Scalar.new(value, nil, nil, true, true, AUTO)
            end
          end
          private_class_method :scalar

          # Force DOUBLE only where yaml.v2 must quote to preserve a string: empty, or a
          # value that would resolve to a non-string / timestamp / base-60. Otherwise AUTO
          # lets libyaml make the same plain/single/double/literal choice OPA does.
          # @return [Integer]
          def self.string_style(string)
            return DOUBLE if string.empty? || ScalarResolver.ambiguous?(string)
            return DOUBLE if TIMESTAMP.match?(string) || BASE60.match?(string)
            return LITERAL if string.include?("\n")

            AUTO
          end
          private_class_method :string_style

          # @return [Psych::Nodes::Sequence]
          def self.sequence(array)
            node = Psych::Nodes::Sequence.new(nil, nil, true, BLOCK_SEQ)
            array.each { |item| node.children << build_node(item) }
            node
          end
          private_class_method :sequence

          # Rego sets are unordered; OPA marshals them deterministically. Sort by OPA's
          # canonical term order (verified via opa eval): null < bool < number < string <
          # array < object < set — note a nested set ranks ABOVE an object, not as its
          # array form.
          # @return [Array<untyped>]
          def self.sorted_set(set)
            set.to_a.sort_by { |element| term_sort_key(element) }
          end
          private_class_method :sorted_set

          # Object keys are compared by term order too (OPA: {2:_} < {10:_} numerically,
          # {true:_} < {1:_} by rank), so recurse into keys rather than stringifying them.
          # @return [Array<untyped>]
          def self.term_sort_key(element)
            case element
            when false then [1, 0]
            when true then [1, 1]
            when Numeric then [2, element]
            when String then [3, element]
            when Array then [4, element.map { |item| term_sort_key(item) }]
            when Hash then [5, sorted_pairs(element)]
            when Set then [6, sorted_set(element).map { |item| term_sort_key(item) }]
            else [0, 0] # null
            end
          end
          private_class_method :term_sort_key

          # Computes each key's sort tuple once (key + value), then sorts by the key tuple —
          # avoiding a second term_sort_key(key) pass while sorting.
          # @return [Array<untyped>]
          def self.sorted_pairs(hash)
            hash.map { |key, value| [term_sort_key(key), term_sort_key(value)] }.sort_by(&:first)
          end
          private_class_method :sorted_pairs

          # OPA stringifies object keys, then yaml.v2 sorts them with its `keyList` natural
          # order (digit runs compared numerically, so "item2" < "item10" and "2" < "10"),
          # not lexicographically. A non-string Rego key is valid, so build each value from
          # its own entry.
          # @return [Psych::Nodes::Mapping]
          def self.mapping(hash)
            node = Psych::Nodes::Mapping.new(nil, nil, true, BLOCK_MAP)
            hash.map { |key, value| [key_string(key), value] }
                .sort { |left, right| natural_compare(left.first, right.first) }
                .each do |string_key, value|
                  node.children << scalar(string_key, string_style(string_key))
                  node.children << build_node(value)
                end
            node
          end
          private_class_method :mapping

          # Port of gopkg.in/yaml.v2's keyList.Less (v2.4.0) string path — OPA's keys are
          # strings post-JSON, so only that branch applies. Digit runs compare numerically,
          # letters lexicographically, and a digit sorts before a letter.
          # @return [Integer] -1, 0, or 1
          def self.natural_compare(left, right)
            lhs = left.chars
            rhs = right.chars
            index = 0
            while index < lhs.length && index < rhs.length
              return compare_at(lhs, rhs, index) unless lhs[index] == rhs[index]

              index += 1
            end
            lhs.length <=> rhs.length
          end
          private_class_method :natural_compare

          # Compares the two key strings at their first differing rune (index).
          # @return [Integer]
          def self.compare_at(lhs, rhs, index)
            left_alpha = letter?(lhs[index])
            right_alpha = letter?(rhs[index])
            return lhs[index] <=> rhs[index] if left_alpha && right_alpha
            return left_alpha ? 1 : -1 if left_alpha || right_alpha

            compare_digit_runs(lhs, rhs, index)
          end
          private_class_method :compare_at

          # Both differing runes are digits: compare the whole runs numerically, then by
          # length (leading zeros), then by rune — mirroring keyList.Less.
          # @return [Integer]
          def self.compare_digit_runs(lhs, rhs, index)
            bias = leading_zero_bias(lhs, rhs, index)
            left_value, left_end = digit_run(lhs, index, bias)
            right_value, right_end = digit_run(rhs, index, bias)
            return left_value <=> right_value unless left_value == right_value
            return left_end <=> right_end unless left_end == right_end

            lhs[index] <=> rhs[index]
          end
          private_class_method :compare_digit_runs

          # @return [Array(Integer, Integer)] numeric value of the run (offset by bias) and its end index
          # NOTE: Ruby integers are arbitrary precision, so a >= 2^63 digit run sorts
          # numerically; yaml.v2's int64 accumulator wraps there, so OPA can order such
          # huge-numeric keys differently. Documented divergence (correct over bug-for-bug).
          def self.digit_run(chars, index, bias)
            value = bias
            cursor = index
            while cursor < chars.length && digit?(chars[cursor])
              value = (value * 10) + chars[cursor].to_i
              cursor += 1
            end
            [value, cursor]
          end
          private_class_method :digit_run

          # keyList's leading-zero tie-break: if a non-zero digit precedes the run in the
          # left key, both run values start at 1 so a shorter (fewer-leading-zero) run wins.
          # @return [Integer]
          def self.leading_zero_bias(lhs, rhs, index)
            return 0 unless lhs[index] == "0" || rhs[index] == "0"

            position = index - 1
            while position >= 0 && digit?(lhs[position])
              return 1 unless lhs[position] == "0"

              position -= 1
            end
            0
          end
          private_class_method :leading_zero_bias

          # ASCII-only: non-ASCII decimal digits can't reach here via OPA's JSON-stringified keys.
          # @return [bool]
          def self.digit?(char)
            char.between?("0", "9")
          end
          private_class_method :digit?

          # @return [bool]
          def self.letter?(char)
            char.match?(/\p{L}/)
          end
          private_class_method :letter?

          # The string form of an object key (mirrors how OPA stringifies map keys).
          # @return [String]
          def self.key_string(key)
            case key
            when String then sanitize(key)
            when Float then float_string(key)
            when true then "true"
            when false then "false"
            when nil then "null"
            else key.to_s
            end
          end
          private_class_method :key_string

          # Go strconv.FormatFloat(f, 'g', -1, 64): shortest digits, scientific when the
          # decimal exponent is < -4 or >= the precision (6 for shortest 'g').
          # @return [String]
          def self.float_string(float)
            raise MarshalError, "non-finite number" unless float.finite?
            return float.to_s.start_with?("-") ? "-0" : "0" if float.zero?

            digits, point = shortest_digits(float.abs)
            exponent = point - 1
            body = exponent < -4 || exponent >= 6 ? scientific(digits, exponent) : fixed(digits, point)
            float.negative? ? "-#{body}" : body
          end

          # Extracts the shortest significant digits and the decimal-point position such
          # that value == 0.<digits> * 10**point. Ruby's Float#to_s gives shortest digits.
          # @return [Array(String, Integer)]
          # :reek:TooManyStatements
          def self.shortest_digits(float)
            mantissa, exponent = float.to_s.split(/e/i)
            integer_part, fraction = mantissa.to_s.split(".")
            integer_part = integer_part.to_s
            combined = integer_part + fraction.to_s
            without_leading = combined.sub(/\A0+/, "")
            point = integer_part.length + (exponent || "0").to_i - (combined.length - without_leading.length)
            digits = without_leading.sub(/0+\z/, "")
            digits.empty? ? ["0", 1] : [digits, point]
          end
          private_class_method :shortest_digits

          # @return [String]
          def self.fixed(digits, point)
            return "0.#{"0" * -point}#{digits}" if point <= 0
            return digits + ("0" * (point - digits.length)) if point >= digits.length

            "#{digits[0...point]}.#{digits[point..]}"
          end
          private_class_method :fixed

          # @return [String]
          def self.scientific(digits, exponent)
            mantissa = digits.length == 1 ? digits : "#{digits[0]}.#{digits[1..]}"
            "#{mantissa}e#{exponent.negative? ? "-" : "+"}#{format("%02d", exponent.abs)}"
          end
          private_class_method :scientific
        end
      end
    end
  end
end
# rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/ModuleLength
