# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Uri
        # Port of Go's url.URL.String / EscapedPath / EscapedFragment / Userinfo.String
        # (src/net/url/url.go): re-serialize parsed Components back to a URL string. crypto.x509's
        # URIStrings field is exactly this serialization of each URI SAN. Lives apart from the parse
        # driver so parser.rb stays under RubyCritic's complexity budget; reopens Parser so the mode
        # constants and escape/unescape resolve via lexical scope.
        module Parser
          # @param components [Components]
          # @return [String]
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
          # :reek:TooManyStatements -- a faithful single-function port of url.URL.String().
          def self.string(components)
            buf = +""
            scheme = components.scheme.to_s
            buf << scheme << ":" unless scheme.empty?
            opaque = components.opaque.to_s
            return finish_query_fragment(buf << opaque, components) unless opaque.empty?

            write_authority(buf, components)
            path = escaped_path(components)
            buf << "/" if !path.empty? && path[0] != "/" && !components.host.to_s.empty?
            buf << "./" if buf.empty? && path.split("/", 2).first.to_s.include?(":")
            buf << path
            finish_query_fragment(buf, components)
          end
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength

          # Append the ?query and #fragment tail (shared by the opaque and hierarchical branches).
          def self.finish_query_fragment(buf, components)
            raw_query = components.raw_query.to_s
            buf << "?" << raw_query if components.force_query || !raw_query.empty?
            buf << "#" << escaped_fragment(components) unless components.fragment.to_s.empty?
            buf
          end
          private_class_method :finish_query_fragment

          # The "//user@host" authority, written only when one of scheme/host/user is present and the
          # host is not an omitted-empty authority (Go's String() authority block).
          # :reek:TooManyStatements -- a faithful port of url.URL.String()'s authority block.
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
          def self.write_authority(buf, components)
            host = components.host.to_s
            user = components.user
            host_empty = host.empty?
            return if host_empty && !user && (components.scheme.to_s.empty? || components.omit_host)

            buf << "//" if !host_empty || !components.path.to_s.empty? || user
            buf << userinfo_string(user) << "@" if user
            buf << escape(host, HOST) unless host_empty
          end
          private_class_method :write_authority
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

          # Port of Userinfo.String: re-escape the (decoded) username and, when present, password.
          def self.userinfo_string(userinfo)
            username, separator, password = userinfo.partition(":")
            encoded = escape(unescape(username, USER_PASSWORD).to_s, USER_PASSWORD)
            return encoded if separator.empty?

            "#{encoded}:#{escape(unescape(password, USER_PASSWORD).to_s, USER_PASSWORD)}"
          end
          private_class_method :userinfo_string

          # Port of EscapedPath: prefer RawPath when it is a VALID encoding of Path, else default-escape
          # Path. "Valid" means both validEncoded(RawPath) (no byte the path mode would escape, outside the
          # allowlist) AND that it decodes back to Path — so a RawPath carrying a raw must-escape byte (a
          # space, a rune >= 0x80, `" < > \ ^ \` { | }`) is re-escaped, not preserved.
          # Public: the canonical-URI form reused by providers.aws.sign_req's SigV4 canonical request.
          def self.escaped_path(components)
            raw = components.raw_path.to_s
            path = components.path.to_s
            return raw if !raw.empty? && valid_encoded?(raw, PATH) && unescape(raw, PATH) == path
            return "*" if path == "*"

            escape(path, PATH)
          end

          # Port of net/url validEncoded: every byte is either in the explicit allowlist (sub-delims plus
          # `: @ [ ] %`, matching Go's char-literal switch) or one the given mode would not escape.
          VALID_ENCODED_ALLOW = "!$&'()*+,;=:@[]%".bytes.freeze

          def self.valid_encoded?(string, mode)
            string.each_byte.all? { |byte| VALID_ENCODED_ALLOW.include?(byte) || !should_escape?(byte, mode) }
          end
          private_class_method :valid_encoded?

          # Port of EscapedFragment: prefer RawFragment when it decodes back to Fragment.
          def self.escaped_fragment(components)
            raw = components.raw_fragment.to_s
            fragment = components.fragment.to_s
            return raw if !raw.empty? && unescape(raw, FRAGMENT) == fragment

            escape(fragment, FRAGMENT)
          end
          private_class_method :escaped_fragment
        end
      end
    end
  end
end
