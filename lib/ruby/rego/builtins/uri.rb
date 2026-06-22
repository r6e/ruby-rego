# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "uri/parser"

# rubocop:disable Naming/PredicatePrefix -- is_valid is the OPA builtin handler name (uri.is_valid).
module Ruby
  module Rego
    module Builtins
      # URI builtins (uri.parse, uri.is_valid), matching OPA's topdown/uri.go — thin wrappers over
      # Go's net/url.Parse (ported in uri/parser.rb).
      #
      # uri.parse returns an object with only the fields OPA exposes — scheme, hostname, port, path,
      # raw_path, raw_query, fragment — each present only when non-empty (raw_path is present
      # whenever path is, as RawPath-or-Path). userinfo and the opaque component are dropped. A
      # string that net/url.Parse rejects is undefined.
      #
      # uri.is_valid is false for a non-string or the empty string (OPA rejects "" deliberately,
      # though RFC 3986 permits it), and otherwise reports whether net/url.Parse succeeds.
      module Uri
        extend RegistryHelpers

        URI_FUNCTIONS = {
          "uri.parse" => { arity: 1, handler: :parse },
          "uri.is_valid" => { arity: 1, handler: :is_valid }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, URI_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param value [Ruby::Rego::Value]
        # @return [Hash, Ruby::Rego::UndefinedValue]
        # :reek:NilCheck -- nil is Parser.parse's error sentinel (Go's url.Parse failure -> undefined).
        # :reek:TooManyStatements -- linear: type guard, encoding guard, parse, shape result.
        def self.parse(value)
          Base.assert_type(value, expected: StringValue, context: "uri.parse")
          string = value.value
          return UndefinedValue.new unless parseable_encoding?(string)

          components = Parser.parse(string)
          components.nil? ? UndefinedValue.new : uri_object(components)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        # :reek:NilCheck -- nil is Parser.parse's error sentinel; valid iff it returns Components.
        def self.is_valid(value)
          return BooleanValue.new(false) unless value.is_a?(StringValue)

          string = value.value
          BooleanValue.new(parseable_encoding?(string) && !string.empty? && !Parser.parse(string).nil?)
        end

        # net/url is byte-oriented, so the parser ingests raw bytes (a BINARY string from
        # base64.decode parses exactly as OPA's does — e.g. base64.decode("4oKsLw==") -> "€/").
        # Reject only strings whose encoding makes net/url's byte/char operations raise rather than
        # return cleanly: an invalid-encoding string (String#count/#split/#downcase raise on it) or
        # an ASCII-incompatible one (UTF-16/32 breaks String#rindex(":")). Neither is reachable
        # through Rego — base64.decode yields ASCII-8BIT and input/literals are valid UTF-8 — so this
        # only guards the public Ruby API. The convention mirrors net.rb's parse_addr.
        def self.parseable_encoding?(string)
          Base.byte_safe_encoding?(string)
        end
        private_class_method :parseable_encoding?

        # Build the result object, including each field only when present (mirroring OPA's
        # builtinURIParse). hostname/port are split from the raw host.
        # :reek:TooManyStatements -- one field per OPA-exposed component; flat by design.
        def self.uri_object(components)
          object = {} # : Hash[String, untyped]
          host = components.host.to_s
          add(object, "scheme", components.scheme)
          add(object, "hostname", Parser.hostname(host))
          add(object, "port", Parser.port(host))
          add_path(object, components)
          add(object, "raw_query", components.raw_query)
          add(object, "fragment", components.fragment)
          object
        end
        private_class_method :uri_object

        # :reek:NilCheck -- a nil/empty path is the "no path component" case (omitted from output).
        def self.add_path(object, components)
          path = components.path
          return if path.nil? || path.empty?

          object["path"] = path
          # raw_path is always set alongside path, as cmp.Or(RawPath, Path) (OPA's contract).
          object["raw_path"] = components.raw_path || path
        end
        private_class_method :add_path

        # :reek:NilCheck -- a nil/empty field is omitted (OPA includes only present components).
        def self.add(object, key, value)
          object[key] = value unless value.nil? || value.empty?
        end
        private_class_method :add
      end
    end
  end
end
# rubocop:enable Naming/PredicatePrefix

Ruby::Rego::Builtins::Uri.register!
