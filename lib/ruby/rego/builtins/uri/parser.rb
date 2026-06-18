# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Uri
        # A faithful port of Go's net/url.Parse (src/net/url/url.go), the parser OPA's uri.parse /
        # uri.is_valid delegate to. Ruby's stdlib URI diverges (it is stricter and lacks Go's
        # RawPath/host quirks), so the algorithm is ported directly rather than adapted.
        #
        # Only the fields OPA exposes are kept on Components — scheme, host, path, raw_path,
        # raw_query, fragment — but the full parse (userinfo validation, opaque branch, host/port
        # rules) runs so the accept/undefined set matches Go exactly. Percent-decoding yields raw
        # bytes (a UTF-8-tagged string that may be invalid UTF-8 for sequences like %FF), matching
        # the gem's urlquery.decode and Go's byte-oriented url.Path.
        module Parser
          # unescape/escape modes (Go's `encoding` enum); only the ones the parse path uses.
          PATH = :path
          HOST = :host
          ZONE = :zone
          USER_PASSWORD = :user_password
          FRAGMENT = :fragment

          # The broken-down URL fields OPA reads. host is the raw authority host[:port]; hostname
          # and port are split lazily for output. opaque/omit_host are internal flow only.
          Components = Struct.new(:scheme, :host, :path, :raw_path, :raw_query, :fragment, keyword_init: true)

          # Parse a raw URI, returning Components or nil when Go's url.Parse would error.
          # @param raw [String]
          # @return [Components, nil]
          # :reek:TooManyStatements -- a faithful single-function port of Go's Parse() (fragment split).
          def self.parse(raw)
            base, _, frag = raw.partition("#")
            url = parse_url(base, via_request: false)
            return nil unless url
            return url if frag.empty? && !raw.include?("#")

            decoded = unescape(frag, FRAGMENT)
            return nil unless decoded

            url.fragment = decoded
            url
          end

          # Port of net/url.parse(rawURL, viaRequest=false). Returns Components or nil on error.
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength
          # :reek:TooManyStatements -- a faithful single-function port of Go's parse().
          def self.parse_url(raw, via_request:)
            return nil if contains_ctl_byte?(raw)

            url = Components.new
            return path_only(url, "*") if raw == "*"

            scheme, rest = get_scheme(raw) || (return nil)
            scheme = scheme.downcase
            url.scheme = scheme
            rest = split_query(url, rest)

            unless rest.start_with?("/")
              return url unless scheme.empty? # rootless path with scheme -> opaque (no path)
              return nil if first_segment_has_colon?(rest)
            end

            if authority?(scheme, rest, via_request)
              authority, rest = split_authority(rest)
              url.host = parse_authority(authority) || (return nil)
            end
            set_path(url, rest) ? url : nil
          end
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/MethodLength
          private_class_method :parse_url

          def self.path_only(url, path)
            url.path = path
            url
          end
          private_class_method :path_only

          # The raw_query split: a lone trailing `?` (ForceQuery) carries no raw_query; otherwise
          # everything after the first `?` is the (raw) query.
          def self.split_query(url, rest)
            if rest.end_with?("?") && rest.count("?") == 1
              rest[0...-1].to_s
            else
              before, sep, query = rest.partition("?")
              url.raw_query = query unless sep.empty?
              before
            end
          end
          private_class_method :split_query

          def self.first_segment_has_colon?(rest)
            rest.split("/", 2).first.to_s.include?(":")
          end
          private_class_method :first_segment_has_colon?

          # Whether `rest` introduces a `//authority` (Go's condition).
          def self.authority?(scheme, rest, via_request)
            (!scheme.empty? || (!via_request && !rest.start_with?("///"))) && rest.start_with?("//")
          end
          private_class_method :authority?

          # Split "//authority/path" into [authority, path].
          def self.split_authority(rest)
            after = rest[2..].to_s
            index = after.index("/")
            index ? [after[0...index].to_s, after[index..].to_s] : [after, ""]
          end
          private_class_method :split_authority

          # Port of getScheme: returns [scheme, rest], or nil on error (a leading ":"). An empty
          # scheme (relative URL) is returned as ["", raw].
          # rubocop:disable Metrics/MethodLength
          # :reek:TooManyStatements
          def self.get_scheme(raw)
            raw.each_char.with_index do |char, index|
              at_start = index.zero?
              case char
              when "a".."z", "A".."Z"
                next
              when "0".."9", "+", "-", "."
                return ["", raw] if at_start
              when ":"
                return nil if at_start

                return [raw[0...index].to_s, raw[(index + 1)..].to_s]
              else
                return ["", raw]
              end
            end
            ["", raw]
          end
          # rubocop:enable Metrics/MethodLength
          private_class_method :get_scheme

          # Port of setPath: decode the path, and keep raw_path only when the default re-escape of
          # the decoded path differs from the original (Go's RawPath invariant). Returns success.
          # rubocop:disable Naming/PredicateMethod
          def self.set_path(url, escaped)
            path = unescape(escaped, PATH) || (return false)
            url.path = path
            url.raw_path = escape(path, PATH) == escaped ? nil : escaped
            true
          end
          # rubocop:enable Naming/PredicateMethod
          private_class_method :set_path

          # Port of stringContainsCTLByte: any byte < 0x20 or == 0x7f.
          def self.contains_ctl_byte?(string)
            string.each_byte.any? { |byte| byte < 0x20 || byte == 0x7f }
          end
          private_class_method :contains_ctl_byte?
        end
      end
    end
  end
end

require_relative "parser/escaping"
require_relative "parser/host"
