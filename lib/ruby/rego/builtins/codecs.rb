# frozen_string_literal: true

require "json"
require "base64"
require "cgi"
require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "codecs/url_query"
require_relative "codecs/json_format"

# rubocop:disable Metrics/ModuleLength
module Ruby
  module Rego
    module Builtins
      # Built-in encoding/decoding helpers (json, base64, base64url, hex, urlquery).
      module Codecs
        extend RegistryHelpers

        CODEC_FUNCTIONS = {
          "json.marshal" => { arity: 1, handler: :json_marshal },
          "json.unmarshal" => { arity: 1, handler: :json_unmarshal },
          "json.is_valid" => { arity: 1, handler: :json_is_valid },
          "base64.encode" => { arity: 1, handler: :base64_encode },
          "base64.decode" => { arity: 1, handler: :base64_decode },
          "base64.is_valid" => { arity: 1, handler: :base64_is_valid },
          "base64url.encode" => { arity: 1, handler: :base64url_encode },
          "base64url.encode_no_pad" => { arity: 1, handler: :base64url_encode_no_pad },
          "base64url.decode" => { arity: 1, handler: :base64url_decode },
          "hex.encode" => { arity: 1, handler: :hex_encode },
          "hex.decode" => { arity: 1, handler: :hex_decode },
          "urlquery.encode" => { arity: 1, handler: :urlquery_encode },
          "urlquery.encode_object" => { arity: 1, handler: :urlquery_encode_object },
          "urlquery.decode" => { arity: 1, handler: :urlquery_decode },
          "urlquery.decode_object" => { arity: 1, handler: :urlquery_decode_object }
        }.freeze

        # A `%` not followed by two hex digits — a malformed percent-escape that OPA (Go's
        # url.QueryUnescape) rejects but CGI.unescape would pass through.
        MALFORMED_PERCENT = /%(?![0-9a-fA-F]{2})/

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, CODEC_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # Compact JSON with object keys sorted, sets rendered as sorted arrays, and
        # Go-style HTML escaping, matching OPA's json.marshal output.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.json_marshal(value)
          StringValue.new(escape_html(JSON.generate(jsonify(value.to_ruby))))
        rescue JSON::JSONError, ArgumentError => e
          # Values that cannot be marshaled to JSON yield undefined rather than
          # aborting evaluation: non-finite numbers (JSON::GeneratorError), over-deep
          # nesting (JSON::NestingError, a DoS safeguard), and a NaN inside a set,
          # which makes set-ordering's comparison raise ArgumentError.
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Cannot marshal value to JSON: #{e.message}",
            expected: "finite, depth-bounded JSON value",
            actual: e.class.name,
            context: "json.marshal",
            location: nil
          )
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        def self.json_unmarshal(value)
          string = string_arg(value, "json.unmarshal")
          decoded("json.unmarshal") { Value.from_ruby(JSON.parse(string)) }
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.json_is_valid(value)
          JSON.parse(string_arg(value, "json.is_valid"))
          BooleanValue.new(true)
        rescue JSON::ParserError
          BooleanValue.new(false)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.base64_encode(value)
          StringValue.new(Base64.strict_encode64(string_arg(value, "base64.encode")))
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.base64_decode(value)
          string = string_arg(value, "base64.decode")
          decoded("base64.decode") { StringValue.new(Base64.strict_decode64(string)) }
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.base64_is_valid(value)
          Base64.strict_decode64(string_arg(value, "base64.is_valid"))
          BooleanValue.new(true)
        rescue ArgumentError
          BooleanValue.new(false)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.base64url_encode(value)
          StringValue.new(Base64.urlsafe_encode64(string_arg(value, "base64url.encode")))
        end

        # OPA accepts both padded and unpadded URL-safe base64, so missing padding
        # is restored before decoding.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.base64url_decode(value)
          string = string_arg(value, "base64url.decode")
          decoded("base64url.decode") { StringValue.new(Base64.urlsafe_decode64(restore_padding(string))) }
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.hex_encode(value)
          StringValue.new(string_arg(value, "hex.encode").unpack1("H*").to_s)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.hex_decode(value)
          string = string_arg(value, "hex.decode")
          decoded("hex.decode") do
            raise ArgumentError, "invalid hex string" unless string.match?(/\A(?:[0-9a-fA-F]{2})*\z/)

            StringValue.new([string].pack("H*"))
          end
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.urlquery_encode(value)
          StringValue.new(CGI.escape(string_arg(value, "urlquery.encode")))
        end

        # OPA (Go's url.QueryUnescape) rejects malformed percent-escapes; CGI.unescape
        # passes them through, so they are validated and rejected to match OPA.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.urlquery_decode(value)
          string = string_arg(value, "urlquery.decode")
          decoded("urlquery.decode") do
            raise ArgumentError, "invalid percent-encoding" if string.match?(MALFORMED_PERCENT)

            StringValue.new(CGI.unescape(string))
          end
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.base64url_encode_no_pad(value)
          StringValue.new(Base64.urlsafe_encode64(string_arg(value, "base64url.encode_no_pad"), padding: false))
        end

        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [String]
        def self.string_arg(value, context)
          Base.assert_type(value, expected: StringValue, context: context)
          value.value
        end
        private_class_method :string_arg

        # Converts a decode failure into an undefined result (via the registry's
        # BuiltinArgumentError handling) instead of raising out of evaluation.
        #
        # @param context [String]
        # @return [Ruby::Rego::Value]
        def self.decoded(context)
          yield
        rescue ArgumentError, JSON::ParserError, EncodingError => e
          # EncodingError covers a non-ASCII-compatible string (e.g. UTF-16 supplied via the
          # Ruby API, never via JSON/Rego input) reaching a String/regex op — yield undefined
          # rather than letting it escape as a hard error.
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Invalid #{context} input: #{e.message}",
            expected: "valid #{context} input",
            actual: "invalid",
            context: context,
            location: nil
          )
        end
        private_class_method :decoded

        # Restores '=' padding so unpadded URL-safe base64 decodes (OPA is lenient).
        #
        # @param string [String]
        # @return [String]
        def self.restore_padding(string)
          remainder = string.length % 4
          remainder.zero? ? string : string + ("=" * (4 - remainder))
        end
        private_class_method :restore_padding
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength

Ruby::Rego::Builtins::Codecs.register!
