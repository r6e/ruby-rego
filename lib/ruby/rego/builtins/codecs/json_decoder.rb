# frozen_string_literal: true

require "strscan"
require_relative "../base"
require_relative "../../number"

module Ruby
  module Rego
    module Builtins
      module Codecs
        # A strict JSON decoder (RFC 8259 / Go encoding/json, which OPA uses) that PRESERVES number text:
        # a JSON number becomes a Ruby::Rego::Number (non-integer) or an exact Integer, matching OPA's
        # json.Number model, instead of collapsing to a Float (1.50 -> 1.5, 1e999 -> Infinity, large
        # integers losing precision). Shared by json.unmarshal / json.is_valid / io.jwt.decode and the CLI
        # input/data loader so all "parse untrusted JSON to Rego values" paths agree.
        #
        # Strict like Go's encoding/json (verified against `opa eval` 1.17): rejects comments, trailing
        # commas, leading zeros, a bare `.5` / `1.`, NaN/Infinity, and trailing content; duplicate object
        # keys take the last value. Comment / trailing-comma rejection also closes the one dangerous
        # gem-wide leniency Ruby's JSON.parse had (it accepted // and /* */ comments OPA rejects).
        #
        # TOTALITY (the contract — the registry rescues only BuiltinArgumentError, callers rescue
        # ParseError): MAX_DEPTH fires on the way DOWN, before this parser's own recursion — and the
        # subsequent recursive Value.from_ruby — can overflow the C stack (a SystemStackError there is
        # uncatchable). A number beyond the magnitude cap (Number::MAX_MAGNITUDE_EXPONENT, the same bound
        # the lexer applies to literals) raises rather than materialise an astronomically large rational;
        # see parse_number for why this is a DoS-vs-fail-open tradeoff, not a safe gem-stricter divergence.
        # The input is byte-encoding-guarded up front, and string content is scanned by bytes, so binary /
        # invalid-UTF-8 input maps to undefined instead of raising an uncaught error.
        # rubocop:disable Metrics/ModuleLength
        module JsonDecoder
          # Raised on any malformed / out-of-bounds input; callers map it to undefined.
          class ParseError < StandardError; end

          # Bounds both this parser's recursion and the downstream Value.from_ruby recursion. Matches the
          # max_nesting Ruby's JSON.parse used (load-bearing — Value.from_ruby SystemStackErrors far below
          # the C-stack limit). Go allows ~10000; staying at 100 is a documented gem-more-strict divergence.
          MAX_DEPTH = 100

          NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/
          WHITESPACE = /[ \t\n\r]+/
          # JSON string body up to the next quote/backslash/control char (control chars are rejected). A
          # US-ASCII regex (no /n) matches a UTF-8 input character-wise and a binary input byte-wise — both
          # without the "binary regexp against UTF-8" warning, and both preserving content unchanged.
          STRING_CHUNK = /[^"\\\x00-\x1f]+/
          private_constant :NUMBER, :WHITESPACE, :STRING_CHUNK

          # @param string [String]
          # @return [Object] a Ruby value (Number/Integer for JSON numbers; String/true/false/nil/Array/Hash)
          # @raise [ParseError]
          def self.parse(string)
            raise ParseError, "invalid string encoding" unless Base.byte_safe_encoding?(string)

            # Normalize an input in an exotic ascii-compatible encoding (US-ASCII, or a single-byte
            # non-UTF-8 encoding like ISO-8859-1 / Windows-1252 that byte_safe_encoding? admits) to raw
            # bytes, so a string body with a literal high byte plus a multibyte \uXXXX escape goes through
            # the BINARY append path (concat_escape) rather than clashing two incompatible encodings — an
            # uncaught Encoding::CompatibilityError that would break totality (normalize_string_encoding
            # re-tags valid bytes back to UTF-8). UTF-8 and BINARY inputs already take the right path and
            # are used as-is — no copy of the (attacker-controlled, e.g. base64-decoded JWT) bytes.
            string = string.b unless [Encoding::UTF_8, Encoding::BINARY].include?(string.encoding)
            scanner = StringScanner.new(string)
            scanner.skip(WHITESPACE)
            value = parse_value(scanner, 0)
            scanner.skip(WHITESPACE)
            raise ParseError, "trailing content" unless scanner.eos?

            value
          end

          # @return [bool] whether `string` is well-formed strict JSON (json.is_valid)
          #
          # Unlike json.unmarshal, json.is_valid does not flow through Codecs.decoded (which rescues
          # EncodingError), so it rescues EncodingError here too: json.is_valid must return false on any
          # un-parseable input, never let an encoding error escape and abort the policy. parse normalizes
          # non-UTF-8 input to bytes so this is defense-in-depth, but it keeps the totality guarantee local.
          def self.valid?(string)
            parse(string)
            true
          rescue ParseError, EncodingError
            false
          end

          def self.parse_value(scanner, depth)
            raise ParseError, "nesting too deep" if depth > MAX_DEPTH

            case scanner.peek(1)
            when "{" then parse_object(scanner, depth)
            when "[" then parse_array(scanner, depth)
            when '"' then parse_string(scanner)
            when "t", "f", "n" then parse_keyword(scanner)
            when "-", "0".."9" then parse_number(scanner)
            else raise ParseError, "unexpected token"
            end
          end
          private_class_method :parse_value

          # rubocop:disable Metrics/MethodLength, Metrics/AbcSize
          def self.parse_object(scanner, depth)
            scanner.pos += 1 # consume {
            object = {} # @type var object: Hash[String, untyped]
            scanner.skip(WHITESPACE)
            return object if scanner.skip(/\}/)

            loop do
              scanner.skip(WHITESPACE)
              key = parse_string(scanner)
              scanner.skip(WHITESPACE)
              raise ParseError, "expected ':'" unless scanner.skip(/:/)

              scanner.skip(WHITESPACE)
              object[key] = parse_value(scanner, depth + 1) # last duplicate key wins, matching Go
              scanner.skip(WHITESPACE)
              break if scanner.skip(/\}/)
              raise ParseError, "expected ',' or '}'" unless scanner.skip(/,/)
            end
            object
          end
          private_class_method :parse_object

          def self.parse_array(scanner, depth)
            scanner.pos += 1 # consume [
            array = [] # @type var array: Array[untyped]
            scanner.skip(WHITESPACE)
            return array if scanner.skip(/\]/)

            loop do
              scanner.skip(WHITESPACE)
              array << parse_value(scanner, depth + 1)
              scanner.skip(WHITESPACE)
              break if scanner.skip(/\]/)
              raise ParseError, "expected ',' or ']'" unless scanner.skip(/,/)
            end
            array
          end
          private_class_method :parse_array
          # rubocop:enable Metrics/MethodLength, Metrics/AbcSize

          # The magnitude cap (Number::MAX_MAGNITUDE_EXPONENT, ~1e30102) bounds rational materialization:
          # without it, comparing a parsed 1e1000000 would allocate a million-digit rational (a memory
          # DoS). OPA does NOT gate its unmarshal path this way (the cap is OPA's *lexer* limit for source
          # literals) — it evaluates such a number and only panics at a ~19-digit exponent. So this is not
          # a safe "gem-stricter": for a deny guard, a number above the cap goes undefined (deny does not
          # fire) where OPA would compare it and deny — a narrowed-but-not-closed fail-open. The realistic
          # range (1e999 and far beyond) is closed; the residual window above the cap is closed properly by
          # the deferred no-materialize comparison work, not by widening the cap (which re-opens the DoS).
          def self.parse_number(scanner)
            text = scanner.scan(NUMBER) or raise ParseError, "invalid number"
            fractional = text.match?(/[.eE]/) # computed once: drives both the magnitude check and dispatch
            raise ParseError, "number too big" unless Number.magnitude_within_limit?(text, fractional: fractional)

            # A fractional/exponent form, or "-0" (whose canonical Integer form "0" would drop OPA's
            # verbatim sign), stays a text-preserving Number; a plain integer becomes an exact Integer.
            fractional || text == "-0" ? Number.literal(text) : Integer(text, 10)
          end
          private_class_method :parse_number

          def self.parse_keyword(scanner)
            return true if scanner.skip(/true/)
            return false if scanner.skip(/false/)
            return nil if scanner.skip(/null/)

            raise ParseError, "invalid literal"
          end
          private_class_method :parse_keyword

          # rubocop:disable Metrics/MethodLength
          def self.parse_string(scanner)
            raise ParseError, "expected string" unless scanner.skip(/"/)

            # Accumulate in the input's encoding so a binary (base64.decode'd) input keeps its raw bytes
            # and a UTF-8 input stays UTF-8; concat_escape coerces the cross-encoding \uXXXX case.
            result = String.new(encoding: scanner.string.encoding)
            loop do
              chunk = scanner.scan(STRING_CHUNK)
              result << chunk if chunk
              case scanner.peek(1)
              when '"'
                scanner.pos += 1
                break
              when "\\"
                scanner.pos += 1
                concat_escape(result, parse_escape(scanner))
              else
                raise ParseError, "unterminated or control char in string"
              end
            end
            normalize_string_encoding(result)
          end
          private_class_method :parse_string
          # rubocop:enable Metrics/MethodLength

          # A binary (base64.decode'd) input whose decoded string content is in fact valid UTF-8 is
          # re-tagged UTF-8, so the same logical JSON yields the same string regardless of whether it
          # arrived UTF-8-tagged (json.unmarshal) or ASCII-8BIT (io.jwt.decode), and matches OPA's UTF-8
          # output. Genuinely invalid bytes stay ASCII-8BIT (the documented raw-bytes divergence: OPA
          # would replace them with U+FFFD; the gem keeps the raw bytes, and re-serializing such a value
          # via json.marshal is currently undefined — a pre-existing serializer gap, not introduced here).
          def self.normalize_string_encoding(string)
            return string unless string.encoding == Encoding::BINARY

            reinterpreted = string.dup.force_encoding(Encoding::UTF_8)
            reinterpreted.valid_encoding? ? reinterpreted : string
          end
          private_class_method :normalize_string_encoding

          # Appends an escape's text (ASCII control char, or a UTF-8 \uXXXX character) to the accumulator.
          # A multibyte \uXXXX character appended to a binary accumulator is forced to bytes so it does not
          # raise Encoding::CompatibilityError (binary input with unicode escapes stays a byte string).
          def self.concat_escape(result, text)
            result << (result.encoding == Encoding::BINARY ? text.b : text)
          end
          private_class_method :concat_escape

          ESCAPES = { '"' => '"', "\\" => "\\", "/" => "/", "b" => "\b", "f" => "\f",
                      "n" => "\n", "r" => "\r", "t" => "\t" }.freeze
          private_constant :ESCAPES

          # :reek:NilCheck -- get_byte returns nil at end-of-input (a backslash with no following byte);
          # that is the truncated-escape sentinel, mapped to ParseError.
          def self.parse_escape(scanner)
            char = scanner.get_byte
            raise ParseError, "truncated escape" if char.nil?

            escaped = ESCAPES[char] # every value is truthy, so a hit is non-nil — one lookup, not two
            return escaped if escaped
            return parse_unicode_escape(scanner) if char == "u"

            raise ParseError, "invalid escape"
          end
          private_class_method :parse_escape

          # \uXXXX: a non-surrogate is its own character; a high+low pair combines into one character; any
          # unpaired surrogate becomes U+FFFD (matching Go) rather than raising. When a high surrogate is
          # followed by a \uXXXX that is NOT a low surrogate, the follower is left unconsumed (the scanner
          # is rewound) so it is re-processed from scratch — exactly as Go does, letting a second high
          # surrogate pair with a third escape (\ud800😀 -> U+FFFD then the 😀 pair).
          def self.parse_unicode_escape(scanner)
            code = read_hex_quad(scanner)
            return code.chr(Encoding::UTF_8) unless code.between?(0xD800, 0xDFFF)
            return "\u{FFFD}" unless code.between?(0xD800, 0xDBFF) # lone low surrogate

            mark = scanner.pos
            return "\u{FFFD}" unless scanner.skip(/\\u/) # high surrogate at end / not followed by \u

            low = read_hex_quad(scanner)
            return combine_surrogates(code, low) if low.between?(0xDC00, 0xDFFF)

            scanner.pos = mark # follower is not a low surrogate: re-process it independently
            "\u{FFFD}"
          end
          private_class_method :parse_unicode_escape

          def self.combine_surrogates(high, low)
            (((high - 0xD800) << 10) + (low - 0xDC00) + 0x10000).chr(Encoding::UTF_8)
          end
          private_class_method :combine_surrogates

          def self.read_hex_quad(scanner)
            hex = scanner.scan(/\h{4}/) or raise ParseError, "invalid \\u escape"
            hex.to_i(16)
          end
          private_class_method :read_hex_quad
        end
        # rubocop:enable Metrics/ModuleLength
      end
    end
  end
end
