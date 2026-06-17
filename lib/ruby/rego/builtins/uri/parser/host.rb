# frozen_string_literal: true

require "ipaddr"

module Ruby
  module Rego
    module Builtins
      module Uri
        # The host/authority cluster for the URI parser: Go's parseAuthority/parseHost plus the
        # IPv6-literal, port, and userinfo validators (src/net/url/url.go). Lives apart from the
        # parse driver so parser.rb stays under RubyCritic's complexity budget. Reopens Parser, so
        # the mode constants (HOST/ZONE) resolve via lexical scope and unescape/escape are shared.
        module Parser
          # Port of parseAuthority: validates userinfo (discarded) and returns the parsed host,
          # or nil on error.
          # :reek:TooManyStatements -- a faithful single-function port of Go's parseAuthority().
          def self.parse_authority(authority)
            at = authority.rindex("@")
            host = parse_host(at ? authority[(at + 1)..].to_s : authority) || (return nil)
            return host unless at

            valid_userinfo?(authority[0...at].to_s) ? host : nil
          end
          private_class_method :parse_authority

          # Port of parseHost (current net/url): an IPv6 literal in brackets must validate as a
          # genuine IPv6 address (rejecting IPv4); a reg-name allows a multi-colon host (the port
          # is the last colon, matching OPA). Unescapes and returns the host (with brackets and any
          # :port preserved) or nil on error.
          def self.parse_host(host)
            open = host.rindex("[")
            return nil if open&.positive? # a "[" not at the start is an invalid IP-literal
            return parse_bracketed_host(host) if open&.zero?
            return nil if (colon = host.rindex(":")) && !valid_optional_port?(host[colon..].to_s)

            unescape(host, HOST)
          end
          private_class_method :parse_host

          # The "[ipv6%25zone]:port" branch: extract and unescape the bracketed address, require it
          # to be a valid (non-IPv4) IP, and reassemble "[addr]port".
          # :reek:TooManyStatements
          def self.parse_bracketed_host(host)
            close = host.rindex("]") || (return nil)
            colon_port = host[(close + 1)..].to_s
            return nil unless valid_optional_port?(colon_port)

            unescaped_port = unescape(colon_port, HOST) || (return nil)
            unescaped = unescape_bracketed(host[1...close].to_s) || (return nil)
            return nil unless valid_ipv6?(unescaped)

            "[#{unescaped}]#{unescaped_port}"
          end
          private_class_method :parse_bracketed_host

          # Unescape the bracket content; an RFC 6874 zone id (%25...) unescapes under encodeZone.
          # :reek:NilCheck -- nil is unescape's error sentinel; a nil zone index means "no zone".
          def self.unescape_bracketed(content)
            zone = content.index("%25")
            return unescape(content, HOST) if zone.nil?

            host_part = unescape(content[0...zone].to_s, HOST) || (return nil)
            zone_part = unescape(content[zone..].to_s, ZONE) || (return nil)
            host_part + zone_part
          end
          private_class_method :unescape_bracketed

          # Whether `unescaped` (an address, optionally with a "%zone") is a valid IPv6 address —
          # Go's netip.ParseAddr + the !addr.Is4() exclusion of IPv4 literals. A present-but-empty
          # zone ("addr%") is rejected, matching netip's "zone must be non-empty" (a Go 1.26 net/url
          # tightening OPA 1.17 ships). Any invalid input is not a valid IPv6 (Go returns an error,
          # not a panic): IPAddr.new raises ArgumentError on a malformed address AND on a raw
          # non-UTF-8 byte (reachable via a %-decoded host like `[%FF::1]`), so both are caught —
          # never raise out of the parser.
          def self.valid_ipv6?(unescaped)
            address, separator, zone = unescaped.partition("%")
            return false if !separator.empty? && zone.empty?

            IPAddr.new(address).ipv6?
          rescue ArgumentError
            false
          end
          private_class_method :valid_ipv6?

          # Port of validOptionalPort: "" or ":" followed by digits only.
          def self.valid_optional_port?(port)
            return true if port.empty?
            return false unless port.start_with?(":")

            port[1..].to_s.each_char.all? { |char| ("0".."9").cover?(char) }
          end
          private_class_method :valid_optional_port?

          # The non-alphanumeric bytes RFC 3986 §3.2.1 allows in userinfo (sub-delims + ":~%@.-_").
          USERINFO_PUNCT = "-._:~!$&'()*+,;=%@".bytes.freeze

          # Port of validUserinfo. Iterates BYTES (not chars) so a raw non-UTF-8 byte is simply
          # rejected rather than raising — and, like Go's rune scan, any non-ASCII byte is invalid.
          def self.valid_userinfo?(string)
            string.each_byte.all? { |byte| alphanumeric?(byte) || USERINFO_PUNCT.include?(byte) }
          end
          private_class_method :valid_userinfo?

          # Port of Hostname(): the host part of host[:port], stripping IPv6 brackets.
          def self.hostname(host)
            split_host_port(host).first
          end

          # Port of Port(): the numeric port of host[:port], or "".
          def self.port(host)
            split_host_port(host).last
          end

          # Port of splitHostPort.
          # :reek:TooManyStatements -- a faithful single-function port of Go's splitHostPort().
          def self.split_host_port(host_port)
            host = host_port
            port = ""
            colon = host.rindex(":")
            if colon && valid_optional_port?(host[colon..].to_s)
              port = host[(colon + 1)..].to_s
              host = host[0...colon].to_s
            end
            host = host[1...-1].to_s if host.start_with?("[") && host.end_with?("]")
            [host, port]
          end
          private_class_method :split_host_port
        end
      end
    end
  end
end
