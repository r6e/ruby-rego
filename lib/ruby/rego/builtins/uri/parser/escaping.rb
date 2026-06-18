# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Uri
        # The percent-encoding engine for the URI parser: Go's unescape/escape/shouldEscape
        # (src/net/url/url.go) and their hex/sub-delim helpers. Lives apart from the parse
        # driver so parser.rb stays under RubyCritic's complexity budget. Reopens Parser, so
        # the mode constants (PATH/HOST/ZONE/USER_PASSWORD/FRAGMENT) resolve via lexical scope.
        module Parser
          UPPERHEX = "0123456789ABCDEF"

          # Port of unescape: percent-decode `s` under `mode`, returning the decoded string (raw
          # bytes preserved) or nil on a malformed/illegal escape. `+` is left as-is (no query mode).
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength
          # :reek:TooManyStatements
          def self.unescape(string, mode)
            bytes = string.b
            out = +"".b # binary buffer: `<<` appends raw bytes, not codepoints
            index = 0
            while index < bytes.bytesize
              byte = bytes.getbyte(index).to_i # non-nil: index < bytesize
              if byte == 37 # '%'
                hi = bytes.getbyte(index + 1)
                lo = bytes.getbyte(index + 2)
                return nil unless hi && lo && ishex?(hi) && ishex?(lo)

                high = unhex(hi)
                value = (high << 4) | unhex(lo)
                return nil if mode == HOST && high < 8 && !triplet_is_pct25?(bytes, index)
                return nil if mode == ZONE && illegal_zone_byte?(bytes, index, value)

                out << value
                index += 3
              else
                return nil if [HOST, ZONE].include?(mode) && byte < 0x80 && should_escape?(byte, mode)

                out << byte
                index += 1
              end
            end
            out.force_encoding(Encoding::UTF_8)
          end
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength
          private_class_method :unescape

          def self.triplet_is_pct25?(bytes, index)
            bytes.byteslice(index, 3) == "%25"
          end
          private_class_method :triplet_is_pct25?

          def self.illegal_zone_byte?(bytes, index, value)
            !triplet_is_pct25?(bytes, index) && value != 32 && should_escape?(value, HOST)
          end
          private_class_method :illegal_zone_byte?

          # Port of escape (the non-query subset the parse path needs): percent-encode bytes that
          # shouldEscape under `mode`. No `+`-for-space (that is query mode only).
          def self.escape(string, mode)
            out = +"".b # binary buffer: `<<` appends raw bytes, not codepoints
            string.b.each_byte do |byte|
              if should_escape?(byte, mode)
                out << "%" << UPPERHEX[byte >> 4].to_s << UPPERHEX[byte & 15].to_s
              else
                out << byte
              end
            end
            out.force_encoding(Encoding::UTF_8)
          end
          private_class_method :escape

          # Port of shouldEscape for the modes the parse path uses (path, host, zone, fragment,
          # user_password).
          # :reek:TooManyStatements
          def self.should_escape?(byte, mode)
            return false if alphanumeric?(byte)
            return false if [HOST, ZONE].include?(mode) && HOST_SUBDELIMS.include?(byte)

            case byte
            when 45, 95, 46, 126 # - _ . ~
              false
            when 36, 38, 43, 44, 47, 58, 59, 61, 63, 64 # $ & + , / : ; = ? @
              reserved_should_escape?(byte, mode)
            else
              mode == FRAGMENT ? !FRAGMENT_SUBDELIMS.include?(byte) : true
            end
          end
          private_class_method :should_escape?
          # §host sub-delims plus the extras Go allows unescaped in a host/zone.
          HOST_SUBDELIMS = "!$&'()*+,;=:[]<>\"".bytes.freeze
          # Fragment sub-delims Go leaves unescaped.
          FRAGMENT_SUBDELIMS = "!()*".bytes.freeze

          def self.alphanumeric?(byte)
            (97..122).cover?(byte) || (65..90).cover?(byte) || (48..57).cover?(byte)
          end
          private_class_method :alphanumeric?

          # The reserved characters ($&+,/:;=?@): each mode leaves a different subset unescaped.
          # :reek:ControlParameter -- mode-dispatch is the point: a faithful port of Go's per-mode rules.
          def self.reserved_should_escape?(byte, mode)
            case mode
            when PATH then byte == 63 # only '?'
            when USER_PASSWORD then [64, 47, 63, 58].include?(byte) # @ / ? :
            when FRAGMENT then false
            else true
            end
          end
          private_class_method :reserved_should_escape?

          # :reek:NilCheck -- getbyte past the string end yields nil; a truncated %-escape is illegal.
          def self.ishex?(byte)
            return false if byte.nil?

            (48..57).cover?(byte) || (97..102).cover?(byte) || (65..70).cover?(byte)
          end
          private_class_method :ishex?

          def self.unhex(byte)
            case byte
            when 48..57 then byte - 48
            when 97..102 then byte - 97 + 10
            else byte - 65 + 10
            end
          end
          private_class_method :unhex
        end
      end
    end
  end
end
