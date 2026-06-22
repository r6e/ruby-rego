# frozen_string_literal: true

require "date"
require "ipaddr"
require "re2"
require_relative "json_schema"
require_relative "../uri/parser"

module Ruby
  module Rego
    module Builtins
      module Codecs
        # The `format` assertions OPA 1.17 enforces, ported from gojsonschema's format_checkers.go. A format
        # only constrains string instances; a value matches (true) when it conforms OR the format is one OPA
        # does not enforce (idn-hostname, duration, unknown names — annotation-only). The boolean is byte-exact
        # with OPA; rules mirror gojsonschema exactly:
        #
        #   * The lexical regexes are anchored \A..\z. gojsonschema applies Go `regexp` with `^..$`, which in
        #     RE2 (default flags) match whole-text — so a leading/trailing/embedded newline is rejected,
        #     unlike Ruby's line-oriented ^..$. (json-pointer still accepts an embedded newline because its
        #     [^~/] class includes it, in both engines.)
        #   * date/time use Go's time.Parse semantics, not the Times::GoLayout port (which rejects time-only
        #     and year-0 values): a strict structural regex plus a proleptic-Gregorian calendar check
        #     (Date::GREGORIAN — Ruby's default Date is Julian before 1582) and hour/min/sec range checks.
        #   * ipv4/ipv6 mirror Go net.ParseIP + a "."/":" check: IPAddr matches it exactly once zone (%) and
        #     CIDR (/) suffixes — which IPAddr accepts but net.ParseIP does not — are rejected.
        #   * regex reuses the RE2 compile gate (JsonSchema.re2_valid?), the same engine as the pattern keyword.
        #   * uri/uri-reference (and their iri aliases) and uri-template reuse Uri::Parser, the gem's port of
        #     Go net/url.Parse: a value matches when it parses, has no backslash (gojsonschema's explicit
        #     reject), and — for uri/iri — a non-empty scheme; uri-template additionally matches the parsed
        #     path against gojsonschema's template regex via the re2 engine (Go's). iri == uri exactly because
        #     url.Parse already accepts unicode hosts/paths, so no separate IDN logic is needed.
        #   * email/idn-email run Go's net/mail.ParseAddress (a full RFC 5322 address parse, not a "valid
        #     email" regex) via the MailAddress port (json_schema_email). idn-email is the SAME checker.
        #
        # Implemented: the lexical / date-time / net / regex formats, the uri family, and email/idn-email. The
        # remaining names (idn-hostname, duration, unknown) fall through to annotation-only (true).
        module JsonSchema
          # The gojsonschema `format` checkers (format_checkers.go) OPA 1.17 enforces. See the file header.
          module Formats
            # gojsonschema's hostname label, then the dotted regex anchored \A..\z for Go's whole-text ^..$.
            HOST_LABEL = "[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]"
            HOSTNAME = /\A(#{HOST_LABEL})(\.(#{HOST_LABEL}))*\z/
            UUID = /\A[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z/i
            JSON_POINTER = %r{\A(?:/(?:[^~/]|~0|~1)*)*\z}
            RELATIVE_JSON_POINTER = %r{\A(?:0|[1-9][0-9]*)(?:#|(?:/(?:[^~/]|~0|~1)*)*)\z}
            # Go time.Parse layouts: hour is "15" (1-2 digits, <=23), minute/second are "04"/"05" (exactly 2);
            # fractional seconds are an optional run of digits after a period OR comma (Go accepts both, per
            # ISO 8601 §5.6); a zone is "Z" or "+hh:mm"/"-hh:mm" where Go range-checks the offset (hour <=24,
            # minute <=60 — wider than the time-of-day fields). The offset hh:mm is captured so it can be
            # range-checked; an absent zone / "Z" leaves those groups nil (->0, which passes). date-time
            # additionally accepts a bare date or bare time (gojsonschema tries five layouts), and full RFC3339
            # requires an uppercase "T" and a zone.
            DATE = /\A(\d{4})-(\d{2})-(\d{2})\z/
            TIME = /\A(\d{1,2}):(\d{2}):(\d{2})(?:[.,]\d+)?(?:Z|[+-](\d{2}):(\d{2}))?\z/
            RFC3339 = /\A(\d{4})-(\d{2})-(\d{2})T(\d{1,2}):(\d{2}):(\d{2})(?:[.,]\d+)?(?:Z|[+-](\d{2}):(\d{2}))\z/
            # gojsonschema's uri-template path check, verbatim, compiled with the re2 engine (Go's regexp) so it
            # is byte-exact and linear (Ruby's Onigmo would risk backtracking on the nested quantifier).
            URI_TEMPLATE_PATH = RE2::Regexp.new("^([^{]*({[^}]*})?)*$", log_errors: false)

            # @param name [String] the format keyword value
            # @param value [String] the string instance being validated
            # @return [bool]
            # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
            # :reek:ControlParameter :reek:TooManyStatements :reek:DuplicateMethodCall
            def self.match?(name, value)
              case name
              when "hostname" then hostname?(value)
              when "uuid" then re_match?(value, UUID)
              when "json-pointer" then re_match?(value, JSON_POINTER)
              when "relative-json-pointer" then re_match?(value, RELATIVE_JSON_POINTER)
              when "regex" then scannable?(value) && JsonSchema.re2_valid?(value)
              when "date" then date?(value)
              when "time" then time?(value)
              when "date-time" then date?(value) || time?(value) || rfc3339?(value)
              when "ipv4" then ip?(value, ".")
              when "ipv6" then ip?(value, ":")
              when "uri", "iri" then absolute_uri?(value)
              when "uri-reference", "iri-reference" then uri_reference?(value)
              when "uri-template" then uri_template?(value)
              when "email", "idn-email" then email?(value)
              else true # idn-hostname / duration / unknown -> annotation only
              end
            end
            # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength

            # A string the Ruby regex engine can scan without raising: valid in its encoding and either pure
            # ASCII or UTF-8 (a binary high-byte string would raise on `match?`). Rego strings reaching OPA are
            # always UTF-8, so a non-scannable value is unreachable in practice; rejecting it keeps totality.
            def self.scannable?(value)
              value.valid_encoding? && (value.ascii_only? || value.encoding == Encoding::UTF_8)
            end

            # A Ruby-regex format match, total on binary / invalid-encoding input.
            def self.re_match?(value, regexp)
              scannable?(value) && regexp.match?(value)
            end

            # gojsonschema: the hostname regex AND len(input) < 256 (bytes).
            def self.hostname?(value)
              value.bytesize < 256 && re_match?(value, HOSTNAME)
            end

            def self.date?(value)
              with_parts(value, DATE) { |year, month, day| valid_date?(year, month, day) }
            end

            def self.time?(value)
              with_parts(value, TIME) do |hour, minute, second, offset_hour, offset_minute|
                valid_clock?(hour, minute, second) && valid_offset?(offset_hour, offset_minute)
              end
            end

            # rubocop:disable Metrics/ParameterLists -- named date/time/offset fields read clearer than parts[]
            def self.rfc3339?(value)
              with_parts(value, RFC3339) do |year, month, day, hour, minute, second, offset_hour, offset_minute|
                valid_date?(year, month, day) && valid_clock?(hour, minute, second) &&
                  valid_offset?(offset_hour, offset_minute)
              end
            end
            # rubocop:enable Metrics/ParameterLists

            # Yield the numeric capture groups of `regexp` matched against a scannable `value` (absent optional
            # groups arrive as 0) so the caller can range-check named fields; false if it does not match.
            # :reek:NilCheck
            def self.with_parts(value, regexp)
              return false unless scannable?(value)

              match = regexp.match(value)
              return false if match.nil?

              yield(*match.captures.map { |group| group.to_s.to_i })
            end

            # Proleptic-Gregorian calendar validity (Go's time package is proleptic Gregorian; Ruby's default
            # Date switches to Julian before 1582, so pin Date::GREGORIAN).
            def self.valid_date?(year, month, day)
              Date.valid_date?(year, month, day, Date::GREGORIAN)
            end

            def self.valid_clock?(hour, minute, second)
              hour <= 23 && minute <= 59 && second <= 59
            end

            # Go time.Parse range-checks the numeric zone offset more loosely than the clock: hour <=24,
            # minute <=60. Absent zone / "Z" arrive as 0, which passes.
            def self.valid_offset?(offset_hour, offset_minute)
              offset_hour <= 24 && offset_minute <= 60
            end

            # Go net.ParseIP + a separator check. net.ParseIP rejects a zone id (%) and CIDR (/) that Ruby's
            # IPAddr would otherwise accept; otherwise IPAddr matches net.ParseIP exactly (verified
            # differentially). ipv4 also requires a ".", ipv6 a ":". Total: any parse failure -> false.
            def self.ip?(value, separator)
              return false if value.include?("%") || value.include?("/")

              IPAddr.new(value)
              value.include?(separator)
            rescue StandardError
              false
            end

            # Go net/url.Parse (via Uri::Parser) of a value with no backslash. nil if it does not parse, is not
            # scannable (Uri::Parser raises on invalid-UTF-8), or contains a backslash (gojsonschema rejects
            # `\` explicitly, separate from url.Parse). The rescue keeps it total against any other parse error.
            # :reek:NilCheck
            def self.url_components(value)
              return nil unless scannable?(value) && !value.include?("\\")

              Uri::Parser.parse(value)
            rescue StandardError
              nil
            end

            # uri / iri: a parseable URL with a non-empty scheme.
            # :reek:NilCheck
            def self.absolute_uri?(value)
              components = url_components(value)
              !components.nil? && !components.scheme.to_s.empty?
            end

            # uri-reference / iri-reference: a parseable URL (scheme optional).
            # :reek:NilCheck
            def self.uri_reference?(value)
              !url_components(value).nil?
            end

            # uri-template: a parseable URL whose path matches gojsonschema's template regex. The path is
            # percent-DECODED by the parser, so it can hold bytes that are invalid UTF-8 (e.g. `%FF`); Go's
            # regexp engine substitutes U+FFFD for each undecodable byte and keeps matching, whereas re2 won't
            # match an undecodable subject — so scrub the path the same way Go's decoder would first.
            # :reek:NilCheck
            def self.uri_template?(value)
              components = url_components(value)
              !components.nil? && URI_TEMPLATE_PATH.match?(components.path.to_s.scrub("\uFFFD"))
            end

            # email / idn-email: gojsonschema runs both through Go's net/mail.ParseAddress (idn-email is the
            # same checker -- RFC 6532 UTF-8 is allowed in atoms either way). See MailAddress (json_schema_email).
            # The scannable? guard ensures the parser only sees valid UTF-8 (matching Go, which rejects
            # invalid-UTF-8 addresses anyway).
            def self.email?(value)
              scannable?(value) && MailAddress.valid?(value)
            end
          end
        end
      end
    end
  end
end
