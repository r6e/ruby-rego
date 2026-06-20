# frozen_string_literal: true

require "json"
require "base64"
require "cgi"
require_relative "base"
require_relative "base64url"
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
          "json.marshal_with_options" => { arity: 2, handler: :json_marshal_with_options },
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

        # A NUL indent sentinel for json.marshal_with_options: JSON.generate never emits a
        # literal NUL inside a value (it escapes to \u0000) and escape_html ignores it, so it can
        # carry the structural indent through HTML-escaping and be swapped for the real indent.
        INDENT_SENTINEL = "\u0000"

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, CODEC_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # The exact bytes OPA's io.jwt.encode_sign signs for a header/payload object — json.marshal's
        # serialization (sorted keys, sets as sorted arrays, Go HTML escaping of <>& and U+2028/U+2029) as
        # a raw String. Raises BuiltinArgumentError (-> undefined) on a non-marshalable value.
        #
        # Float formatting follows Ruby's Float#to_s (json.marshal's shared number model), so a claim like
        # 1e308 serialises as "1e+308" where Go emits "1e308" — the same gem-wide JSON-number divergence
        # json.marshal/json.unmarshal already carry, not specific to encode_sign. Integers (any magnitude,
        # via Bignum) are byte-exact, so practical JWT claims are unaffected.
        #
        # @param value [Ruby::Rego::Value]
        # @return [String]
        def self.canonical_json(value)
          escape_html(JSON.generate(jsonify(value.to_ruby)))
        rescue JSON::JSONError, ArgumentError => e
          raise_marshal_error(e, "json.marshal")
        end

        # Compact JSON with object keys sorted, sets rendered as sorted arrays, and
        # Go-style HTML escaping, matching OPA's json.marshal output.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.json_marshal(value)
          StringValue.new(canonical_json(value))
        end

        # Compact or pretty-printed JSON, matching OPA's json.marshal_with_options. The options
        # object takes `prefix` and `indent` strings and a `pretty` boolean; pretty-printing is
        # enabled by `pretty: true`, or — when `pretty` is absent — implicitly by supplying a
        # `prefix` or `indent`. Pretty output uses Go's json.MarshalIndent indent-per-depth layout;
        # OPA then prepends the `prefix` to every line, including the first (MarshalIndent itself
        # omits it on line one). A non-object options argument, an unknown option key, a
        # wrongly-typed option value, or an unmarshalable document yields undefined.
        #
        # @param value [Ruby::Rego::Value]
        # @param options_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        # :reek:TooManyStatements
        def self.json_marshal_with_options(value, options_value)
          prefix, indent, pretty = marshal_options(options_value)
          ruby = jsonify(value.to_ruby)
          output = pretty ? pretty_json(ruby, prefix, indent) : escape_html(JSON.generate(ruby))
          StringValue.new(output)
        rescue JSON::JSONError, ArgumentError => e
          raise_marshal_error(e, "json.marshal_with_options")
        end

        # Values that cannot be marshaled to JSON yield undefined rather than aborting
        # evaluation: non-finite numbers (JSON::GeneratorError), over-deep nesting
        # (JSON::NestingError, a DoS safeguard), and a NaN inside a set, which makes
        # set-ordering's comparison raise ArgumentError.
        def self.raise_marshal_error(error, context)
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Cannot marshal value to JSON: #{error.message}",
            expected: "finite, depth-bounded JSON value",
            actual: error.class.name, context: context, location: nil
          )
        end
        private_class_method :raise_marshal_error

        # @return [[String, String, bool]] prefix, indent, pretty
        # :reek:TooManyStatements
        def self.marshal_options(options_value)
          Base.assert_type(options_value, expected: ObjectValue, context: "json.marshal_with_options")
          options = options_value.to_ruby
          options.each_key { |key| validate_option_key(key) }
          prefix = options.key?("prefix") ? string_option("prefix", options["prefix"]) : ""
          indent = options.key?("indent") ? string_option("indent", options["indent"]) : "\t"
          [prefix, indent, marshal_pretty(options)]
        end
        private_class_method :marshal_options

        def self.validate_option_key(key)
          raise_marshal_option_error("unknown key #{key.inspect}") unless %w[prefix indent pretty].include?(key)
        end
        private_class_method :validate_option_key

        # `pretty` if given explicitly; otherwise implied by the presence of `prefix` or `indent`.
        def self.marshal_pretty(options)
          return bool_option(options["pretty"]) if options.key?("pretty")

          options.key?("prefix") || options.key?("indent")
        end
        private_class_method :marshal_pretty

        def self.string_option(key, option)
          option.is_a?(String) ? option : raise_marshal_option_error("#{key} must be a string")
        end
        private_class_method :string_option

        def self.bool_option(option)
          [true, false].include?(option) ? option : raise_marshal_option_error("pretty must be a boolean")
        end
        private_class_method :bool_option

        # Go's json.MarshalIndent form — the prefix prepends the first line and follows every
        # newline (MarshalIndent omits it on line one). The indent/prefix are structural and must
        # NOT be HTML-escaped (only JSON values are), so the body is generated with a NUL-byte
        # indent sentinel — which JSON.generate never emits inside a string value and escape_html
        # never touches — then swapped for the real indent after escaping; the prefix is likewise
        # applied raw, after escaping.
        def self.pretty_json(ruby, prefix, indent)
          generated = JSON.generate(ruby, indent: INDENT_SENTINEL, space: " ", object_nl: "\n", array_nl: "\n")
          # One left-to-right pass replaces each structural newline with newline+prefix and each
          # indent sentinel with the real indent. A single pass (block form) never rescans the
          # inserted text, so a backslash in either string is literal (not a gsub back-reference)
          # and a newline or NUL inside the indent/prefix can't collide with the markers.
          prefix + escape_html(generated).gsub(Regexp.union("\n", INDENT_SENTINEL)) do |marker|
            marker == "\n" ? "\n#{prefix}" : indent
          end
        end
        private_class_method :pretty_json

        def self.raise_marshal_option_error(message)
          Base.raise_argument_error("invalid json.marshal_with_options option: #{message}",
                                    expected: "prefix/indent string or pretty boolean", actual: "invalid",
                                    context: "json.marshal_with_options")
        end
        private_class_method :raise_marshal_option_error

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

        # OPA accepts padded and unpadded URL-safe base64 but rejects the standard-base64 '+'/'/' and
        # non-canonical padding; Base64Url.strict_decode enforces that (shared with io.jwt.decode), and
        # the `decoded` block maps its ArgumentError to undefined.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.base64url_decode(value)
          string = string_arg(value, "base64url.decode")
          decoded("base64url.decode") { StringValue.new(Base64Url.strict_decode(string)) }
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
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength

Ruby::Rego::Builtins::Codecs.register!
