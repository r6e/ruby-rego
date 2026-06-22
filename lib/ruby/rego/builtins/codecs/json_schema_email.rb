# frozen_string_literal: true

require "ipaddr"
require_relative "json_schema_formats"

module Ruby
  module Rego
    module Builtins
      module Codecs
        module JsonSchema
          module Formats
            # A port of Go's net/mail `ParseAddress` (src/net/mail/message.go, go1.26.4 — the Go OPA 1.17.1 is
            # built with), reduced to the boolean gojsonschema's `email`/`idn-email` checkers need: does the
            # value parse as exactly one RFC 5322 address. There is no Ruby gem matching Go's specific
            # acceptance boundary, so this is hand-rolled and differentially verified against `opa eval`.
            #
            # Faithful to Go's quirks: a single-member group `g: a@b;` parses (parseSingleAddress) but a
            # multi-member one does not; a display name + angle-addr `Foo <a@b>` parses; comments are CFWS only
            # as a trailing run or via skipCFWS, so a LEADING comment fails while a trailing one passes; the
            # local-part/`@` boundary skips plain space but not comments (`a (c) @b` fails); a domain-literal
            # `[x]` requires net.ParseIP(x) (so `[127.0.0.1]` and `[::1]` pass but `[IPv6:::1]` fails);
            # atext/qtext/dtext allow any rune >= U+0080 (RFC 6532). RFC 2047 encoded-word decoding in phrases
            # IS replicated to the extent it affects acceptance (Rfc2047.status + consume_phrase): Go's
            # consumePhrase runs mime.WordDecoder.Decode on each atom word. A `=?charset?enc?text?=` whose
            # payload decodes but whose charset is not utf-8/iso-8859-1/us-ascii makes Decode error (rejecting
            # as the first word, else truncating); an empty payload decodes to "" and is dropped; a malformed or
            # undecodable word is kept as raw text. Go 1.26 also buffers a run of consecutive encoded-words and
            # only flushes them to its `words` slice on a following raw word, so a comment after a lone
            # encoded-word run ends the phrase (the CFWS skip is gated on len(words)). Verified differentially
            # against opa across the cross-product (19000+ encoded-word cases).
            #
            # The input is required UTF-8-valid by the caller (Formats#email?), so Go's invalid-UTF-8 error
            # paths can't fire mid-parse. Parsing walks a char-array index (see #initialize) so it stays
            # linear on multibyte input, not string re-slicing or O(@pos) codepoint indexing.
            #
            # rubocop:disable Metrics/ClassLength, Naming/PredicateMethod -- a faithful recursive-descent port;
            # the consume_*/skip_* methods mutate @pos and return success bools (not pure predicates).
            class MailAddress
              SPECIALS = ["(", ")", "<", ">", "[", "]", ":", ";", "@", "\\", ",", "\""].freeze
              # Frozen so the per-character predicates scan a shared array rather than allocating a literal
              # each call (a hot-path GC concern on large inputs).
              WSP = [" ", "\t"].freeze # space / tab (skip_space + wsp?)
              QTEXT_EXCLUDED = ["\\", "\""].freeze # not qtext: backslash, double-quote
              DTEXT_EXCLUDED = ["[", "]", "\\"].freeze # not dtext: brackets, backslash

              # @return [bool] whether `string` is exactly one Go-parseable address.
              def self.valid?(string)
                new(string).single_address?
              end

              def initialize(string)
                # Index a char ARRAY, not the String: CRuby's String#[] by codepoint is O(@pos) for a
                # non-ASCII (multibyte) string, which would make the scan loops O(n²) — a DoS on the RFC 6532
                # UTF-8 input that is explicitly in scope. Array#[] is O(1), so the whole parse stays linear.
                @chars = string.chars
                @pos = 0
                @len = @chars.length
              end

              # Port of parseSingleAddress: one address, then trailing CFWS, then nothing left; a group must
              # have exactly one member.
              # :reek:NilCheck
              def single_address?
                count = parse_address(handle_group: true)
                return false if count.nil?
                return false unless skip_cfws
                return false unless empty?

                count == 1
              end

              private

              def empty? = @pos >= @len
              def peek = @chars[@pos]

              # :reek:ControlParameter -- dispatches on the target char, like Go's consume(c byte).
              def consume(char)
                return false if empty? || @chars[@pos] != char

                @pos += 1
                true
              end

              def skip_space
                @pos += 1 while @pos < @len && wsp?(@chars[@pos])
              end

              # Port of parseAddress(handleGroup): try a bare addr-spec (with an optional trailing comment),
              # else a phrase followed by a group (`:`) or an angle-addr (`<addr-spec>`). Returns the address
              # count (0 for an empty group) or nil on error.
              # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength, Metrics/AbcSize
              # :reek:TooManyStatements :reek:NilCheck :reek:ControlParameter :reek:DuplicateMethodCall
              def parse_address(handle_group:)
                skip_space
                return nil if empty?

                if consume_addr_spec
                  skip_space
                  return nil if !empty? && peek == "(" && !consume_display_name_comment

                  return 1
                end

                unless !empty? && peek == "<"
                  return nil unless consume_phrase
                end

                skip_space
                return consume_group_list if handle_group && consume(":")
                return nil unless consume("<")
                return nil unless consume_addr_spec
                return nil unless consume(">")

                1
              end
              # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength, Metrics/AbcSize

              # Port of consumeAddrSpec, rolling the position back on failure (Go's deferred `*p = orig`).
              # :reek:TooManyStatements :reek:NilCheck
              def consume_addr_spec
                start = @pos
                ok = parse_addr_spec
                @pos = start unless ok
                ok
              end

              # :reek:TooManyStatements :reek:NilCheck
              def parse_addr_spec
                skip_space
                return false if empty?
                return false unless consume_local_part
                return false unless consume("@")

                skip_space
                return false if empty?

                peek == "[" ? consume_domain_literal : !consume_atom(dot: true, permissive: false).nil?
              end

              # local-part = quoted-string (non-empty) | dot-atom.
              # :reek:NilCheck
              def consume_local_part
                return !consume_atom(dot: true, permissive: false).nil? unless peek == "\""

                quoted = consume_quoted_string
                !quoted.nil? && !quoted.empty?
              end

              # Port of consumeGroupList: members separated by ",", terminated by ";". Returns the count or nil.
              # rubocop:disable Metrics/CyclomaticComplexity, Metrics/MethodLength
              # :reek:TooManyStatements :reek:NilCheck :reek:DuplicateMethodCall
              def consume_group_list
                skip_space
                return (skip_cfws ? 0 : nil) if consume(";")

                count = 0
                loop do
                  skip_space
                  member = parse_address(handle_group: false)
                  return nil if member.nil?

                  count += member
                  return nil unless skip_cfws
                  break if consume(";") && skip_cfws
                  return nil unless consume(",")
                end
                count
              end
              # rubocop:enable Metrics/CyclomaticComplexity, Metrics/MethodLength

              # Port of consumeAtom(dot, permissive): a run of atext; permissive=false rejects leading/trailing/
              # double dots. Returns the atom or nil if empty.
              # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
              # :reek:NilCheck :reek:TooManyStatements
              def consume_atom(dot:, permissive:)
                start = @pos
                @pos += 1 while @pos < @len && atext?(@chars[@pos], dot)
                return nil if @pos == start

                # `|| []` only narrows Array#[]'s nilable RBS type for steep; start <= @pos always holds, so
                # the slice is never nil at runtime.
                atom = (@chars[start...@pos] || []).join
                return nil if !permissive && (atom.start_with?(".") || atom.include?("..") || atom.end_with?("."))

                atom
              end
              # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

              # Port of consumeQuotedString (opening '"' at @pos): qtext / WSP / `\`-escaped VCHAR|WSP, closed
              # by '"'. Returns the unquoted content or nil on an unclosed / bad-character string.
              # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
              # rubocop:disable Metrics/PerceivedComplexity
              # :reek:TooManyStatements :reek:NilCheck :reek:DuplicateMethodCall
              def consume_quoted_string
                i = @pos + 1
                content = +""
                escaped = false
                while i < @len
                  char = @chars[i]
                  if escaped
                    return nil unless vchar?(char) || wsp?(char)

                    content << char.to_s
                    escaped = false
                  elsif char == "\\"
                    escaped = true
                  elsif char == "\""
                    @pos = i + 1
                    return content
                  elsif qtext?(char) || wsp?(char)
                    content << char.to_s
                  else
                    return nil
                  end
                  i += 1
                end
                nil
              end
              # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
              # rubocop:enable Metrics/PerceivedComplexity

              # Port of consumeDomainLiteral: `[` dtext* `]` where the dtext must be a net.ParseIP address.
              # :reek:TooManyStatements :reek:NilCheck
              def consume_domain_literal
                return false unless consume("[")

                start = @pos
                while @pos < @len && peek != "]"
                  return false unless dtext?(peek)

                  @pos += 1
                end
                dtext = (@chars[start...@pos] || []).join # `|| []` is a steep type-narrow; never nil (start <= @pos)
                return false unless consume("]")

                parseable_ip?(dtext)
              end

              # Port of consumePhrase (Go 1.26, which OPA 1.17.1 is built with): 1*word, word = quoted-string |
              # dot-atom (permissive), CFWS between words. The atom branch runs Go's decodeRFC2047Word via
              # Rfc2047.status (see there for the verdict definitions). Go 1.26 accumulates a RUN of consecutive
              # RFC 2047 encoded-words in a builder and only appends to the `words` slice when a raw word follows
              # (flushing the run) or at the end; the `len(words) > 0` gate on the comment-consuming CFWS skip
              # therefore stays FALSE while the phrase so far is purely encoded-words — so a comment after a lone
              # encoded-word run ends the phrase. We don't need the phrase text, only the flush bookkeeping:
              # `flushed` IS Go's len(words), `pending` IS sb.Len() > 0 (an unflushed encoded-word run). Per
              # verdict: :charset_error breaks; :empty is a no-op (writes nothing); :encoded starts/continues the
              # pending run (not yet a word); :raw (incl. quoted-string) flushes any run (+1) and counts itself
              # (+1). Returns true once any word is flushed, false when none ever is (Go's err on a wordless
              # phrase).
              # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
              # rubocop:disable Metrics/PerceivedComplexity
              # :reek:TooManyStatements :reek:NilCheck :reek:DuplicateMethodCall
              def consume_phrase
                flushed = 0
                pending = false # a run of non-empty encoded-words awaiting a flush into the word count
                loop do
                  return false if flushed.positive? && !skip_cfws

                  skip_space
                  break if empty?

                  if peek == "\""
                    break if consume_quoted_string.nil?

                    kind = :raw
                  else
                    word = consume_atom(dot: true, permissive: true)
                    break if word.nil?

                    kind = Rfc2047.status(word)
                    break if kind == :charset_error
                  end

                  case kind
                  when :encoded then pending = true
                  when :empty then nil # writes nothing: no flush, no count
                  else # :raw — flush any pending encoded run, then count this word
                    flushed += 1 if pending
                    pending = false
                    flushed += 1
                  end
                end
                flushed += 1 if pending # final flush of a trailing encoded run
                flushed.positive?
              end
              # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
              # rubocop:enable Metrics/PerceivedComplexity

              # Port of skipCFWS: spaces, then balanced `(...)` comments, repeated. Returns false on a malformed
              # comment.
              def skip_cfws
                skip_space
                while consume("(")
                  return false unless consume_comment

                  skip_space
                end
                true
              end

              # Port of consumeComment ('(' already consumed): nested parens with `\`-escape, returns whether
              # balanced.
              # rubocop:disable Metrics/MethodLength
              # :reek:TooManyStatements :reek:DuplicateMethodCall
              def consume_comment
                depth = 1
                until empty? || depth.zero?
                  char = @chars[@pos]
                  if char == "\\" && @len - @pos > 1
                    @pos += 1
                  elsif char == "("
                    depth += 1
                  elsif char == ")"
                    depth -= 1
                  end
                  @pos += 1
                end
                depth.zero?
              end
              # rubocop:enable Metrics/MethodLength

              # Port of consumeDisplayNameComment (trailing comment after an addr-spec). RFC 2047 decode of the
              # comment words is omitted (see the class note).
              def consume_display_name_comment
                consume("(") && consume_comment
              end

              # net.ParseIP equivalence: IPAddr matches it once the zone (%) and CIDR (/) forms IPAddr accepts
              # but net.ParseIP rejects are excluded (verified differentially for the ipv4/ipv6 formats).
              # :reek:UtilityFunction -- a pure net.ParseIP shim; kept here beside its sole caller.
              def parseable_ip?(string)
                return false if string.include?("%") || string.include?("/")

                IPAddr.new(string)
                true
              rescue StandardError
                false
              end

              # All char predicates accept nil (an out-of-bounds read) and return false, so the bounds-guarded
              # call sites stay total without steep narrowing every index.
              # :reek:NilCheck
              def atext?(char, dot)
                return dot if char == "."
                return false if SPECIALS.include?(char)

                vchar?(char)
              end

              # :reek:NilCheck :reek:UtilityFunction
              def vchar?(char)
                return false if char.nil?

                ord = char.ord
                ord.between?(0x21, 0x7E) || ord >= 0x80
              end

              # :reek:UtilityFunction
              def wsp?(char) = WSP.include?(char)

              def qtext?(char)
                return false if QTEXT_EXCLUDED.include?(char)

                vchar?(char)
              end

              def dtext?(char)
                return false if DTEXT_EXCLUDED.include?(char)

                vchar?(char)
              end
            end
            # rubocop:enable Metrics/ClassLength, Naming/PredicateMethod

            # The slice of Go's net/mail decodeRFC2047Word + mime.WordDecoder.Decode that MailAddress'
            # consume_phrase needs (mirroring Go's net/mail -> mime package boundary). All pure byte functions:
            # an encoded-word is structurally `=?charset?encoding?text?=` (>=8 bytes, exactly four `?`, non-empty
            # charset, one-byte encoding) with a decodable B/Q payload; only utf-8/iso-8859-1/us-ascii convert
            # natively, anything else errors. Byte-oriented to mirror Go (len / index / base64 / qDecode on
            # bytes). See the differential coverage in the email spec.
            # :reek:UncommunicativeModuleName -- "Rfc2047" is the RFC number, the canonical name for this spec.
            module Rfc2047
              # Charsets mime.WordDecoder.convert handles without a CharsetReader (EqualFold, i.e. ASCII-case).
              CHARSETS = %w[utf-8 iso-8859-1 us-ascii].freeze

              # How consume_phrase must treat an atom `word`, mirroring Go's decodeRFC2047Word isEncoded/err:
              #   :charset_error - a real encoded-word whose payload decodes but whose charset mime can't
              #                    convert (Go's Decode errors);
              #   :empty         - a real encoded-word with an empty payload, decoding to "" (isEncoded, dropped);
              #   :encoded       - a real encoded-word with non-empty content (isEncoded);
              #   :raw           - anything else: a plain atom, a malformed encoded-word, or one whose B/Q
              #                    payload fails to decode — Go keeps the raw text (isEncoded=false).
              # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
              # :reek:TooManyStatements :reek:DuplicateMethodCall
              def self.status(word)
                bytes = word.b
                return :raw if bytes.bytesize < 8 || !bytes.start_with?("=?") || !bytes.end_with?("?=")
                return :raw unless bytes.count("?") == 4

                charset, rest = bytes[2...-2].to_s.split("?", 2)
                encoding, text = rest.to_s.split("?", 2)
                return :raw if charset.to_s.empty? || encoding.to_s.bytesize != 1
                return :raw unless payload_decodes?(encoding.to_s, text.to_s)
                return :charset_error unless CHARSETS.include?(charset.to_s.downcase)

                # Emptiness of the raw text is exact: no NON-empty payload that passes payload_decodes? can
                # decode to "" (min base64 quantum is 4 chars -> >=1 byte; qDecode never deletes bytes), so we
                # need not actually decode to know the content is empty.
                text.to_s.empty? ? :empty : :encoded
              end
              # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

              # mime `decode`: 'B'/'b' = base64.StdEncoding, 'Q'/'q' = qDecode. Any other encoding byte errors.
              # :reek:ControlParameter -- dispatches on the encoding byte, like Go's decode(encoding, text).
              def self.payload_decodes?(encoding, text)
                case encoding
                when "B", "b" then base64_decodes?(text)
                when "Q", "q" then qdecodes?(text)
                else false
                end
              end

              # base64.StdEncoding.DecodeString success boundary: length a multiple of 4, only alphabet bytes
              # with 0-2 trailing `=` padding. Empty text decodes to empty (success).
              # rubocop:disable Metrics/MethodLength
              # :reek:TooManyStatements
              def self.base64_decodes?(text)
                bytes = text.b
                size = bytes.bytesize
                return true if size.zero?
                return false unless (size % 4).zero?

                pad = 0
                pad += 1 while pad < 2 && bytes.getbyte(size - 1 - pad) == 0x3D

                # Scan the body bytes in place (no substring / no Array#bytes allocation) — like qdecodes?.
                index = 0
                body = size - pad
                while index < body
                  return false unless base64_char?(bytes.getbyte(index))

                  index += 1
                end
                true
              end
              # rubocop:enable Metrics/MethodLength

              # Port of mime.qDecode's per-byte acceptance: `_`, an `=XX` hex escape (needs two hex digits),
              # printable ASCII, or TAB/LF/CR. Any other byte errors. Returns whether the whole run decodes.
              # rubocop:disable Metrics/MethodLength
              # :reek:TooManyStatements :reek:DuplicateMethodCall
              def self.qdecodes?(text)
                bytes = text.b
                index = 0
                size = bytes.bytesize
                while index < size
                  byte = bytes.getbyte(index)
                  if byte == 0x3D # '='
                    return false if index + 2 >= size
                    return false unless hex_byte?(bytes.getbyte(index + 1)) && hex_byte?(bytes.getbyte(index + 2))

                    index += 2
                  elsif !qtext_byte?(byte)
                    return false
                  end
                  index += 1
                end
                true
              end
              # rubocop:enable Metrics/MethodLength

              # :reek:NilCheck
              def self.base64_char?(byte)
                return false if byte.nil?

                (0x41..0x5A).cover?(byte) || (0x61..0x7A).cover?(byte) || (0x30..0x39).cover?(byte) ||
                  byte == 0x2B || byte == 0x2F # '+' '/'
              end

              # qDecode-acceptable raw byte: '_' or printable ASCII (0x20..0x7E) or TAB/LF/CR. nil (an
              # out-of-bounds read) is never acceptable.
              # :reek:NilCheck
              def self.qtext_byte?(byte)
                return false if byte.nil?

                byte == 0x5F || (0x20..0x7E).cover?(byte) || byte == 0x09 || byte == 0x0A || byte == 0x0D
              end

              # :reek:NilCheck
              def self.hex_byte?(byte)
                return false if byte.nil?

                (0x30..0x39).cover?(byte) || (0x41..0x46).cover?(byte) || (0x61..0x66).cover?(byte)
              end
            end
          end
        end
      end
    end
  end
end
