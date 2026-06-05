# frozen_string_literal: true

require "json"
require "base64"
require "cgi"
require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

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

        # Encodes an object as a query string, matching OPA (Go's url.Values.Encode): keys
        # are sorted; a string value emits one pair, an array/set value one pair per element
        # (arrays keep order; sets are sorted and de-duplicated). A non-object, a non-string
        # key, or a value that is not a string or string array/set yields undefined.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.urlquery_encode_object(value)
          Base.assert_type(value, expected: ObjectValue, context: "urlquery.encode_object")
          StringValue.new(query_pairs(value.value).join("&"))
        rescue EncodingError
          # A non-ASCII-compatible key/value (Ruby API only) makes CGI.escape raise; treat
          # it as an invalid object rather than letting it escape.
          raise_invalid_object
        end

        # @param pairs [Hash{Object => Ruby::Rego::Value}]
        # @return [Array<String>]
        def self.query_pairs(pairs)
          keys = pairs.keys
          raise_invalid_object unless keys.all?(String)

          keys.sort.flat_map { |key| key_pairs(key, pairs[key]) }
        end
        private_class_method :query_pairs

        # The escaped `key=value` pairs a single object entry contributes.
        #
        # @param key [String]
        # @param value [Ruby::Rego::Value]
        # @return [Array<String>]
        def self.key_pairs(key, value)
          strings = query_values(value) || raise_invalid_object
          escaped_key = CGI.escape(key)
          strings.map { |string| "#{escaped_key}=#{CGI.escape(string)}" }
        end
        private_class_method :key_pairs

        # The string values a query value contributes, or nil if it is not a string or a
        # string array/set. An array keeps order; a set is sorted and de-duplicated.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Array<String>, nil]
        def self.query_values(value)
          contents = value.value
          case value
          when StringValue then [contents]
          when ArrayValue then string_elements(contents)
          when SetValue then string_elements(contents.to_a)&.sort
          end
        end
        private_class_method :query_values

        # @param elements [Array<Ruby::Rego::Value>]
        # @return [Array<String>, nil]
        def self.string_elements(elements)
          return nil unless elements.all?(StringValue)

          elements.map(&:value)
        end
        private_class_method :string_elements

        # @return [void]
        def self.raise_invalid_object
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Invalid object for urlquery.encode_object",
            expected: "object of string or string array/set values",
            actual: "invalid",
            context: "urlquery.encode_object",
            location: nil
          )
        end
        private_class_method :raise_invalid_object

        # Decodes a query string to an object mapping each key to its array of values,
        # matching OPA (Go's url.ParseQuery). Reuses urlquery.decode's percent validation
        # and unescaping; a malformed percent-escape (in any key or value) yields undefined,
        # as does a literal `;` — Go's ParseQuery rejects it as a separator (a `;` in a value
        # must be percent-encoded).
        #
        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::ObjectValue]
        def self.urlquery_decode_object(value)
          string = string_arg(value, "urlquery.decode_object")
          decoded("urlquery.decode_object") do
            raise ArgumentError, "invalid percent-encoding" if string.match?(MALFORMED_PERCENT)
            raise ArgumentError, "semicolon separator" if string.include?(";")

            ObjectValue.new(grouped_query(string))
          end
        end

        # @param string [String]
        # @return [Hash{String => Array<String>}]
        def self.grouped_query(string)
          pairs = string.split("&").reject(&:empty?).map do |pair|
            key, _, raw_value = pair.partition("=")
            [CGI.unescape(key), CGI.unescape(raw_value)]
          end
          pairs.group_by(&:first).transform_values { |group| group.map(&:last) }
        end
        private_class_method :grouped_query

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

        # Applies Go's encoding/json HTML escaping (OPA's json.Marshal keeps it on):
        # <, >, & and the U+2028/U+2029 separators become \uXXXX inside string content.
        #
        # @param json [String]
        # @return [String]
        def self.escape_html(json)
          json.gsub(/[<>&\u{2028}\u{2029}]/) { |char| format('\u%04x', char.ord) }
        end
        private_class_method :escape_html

        # @param ruby [Object]
        # @return [Object]
        def self.jsonify(ruby)
          case ruby
          when ::Hash then ruby.keys.sort_by(&:to_s).to_h { |key| [key.to_s, jsonify(ruby[key])] }
          when ::Set then sorted_json_array(ruby)
          when ::Array then ruby.map { |element| jsonify(element) }
          else ruby
          end
        end
        private_class_method :jsonify

        # @param set [Set]
        # @return [Array<Object>]
        def self.sorted_json_array(set)
          set.map { |element| jsonify(element) }.sort_by { |element| json_sort_key(element) }
        end
        private_class_method :sorted_json_array

        # Deterministic sort key mirroring OPA's set ordering: by type rank, then
        # value, with composites compared element-wise (not by serialized string).
        #
        # @param element [Object]
        # @return [Array<Object>]
        # rubocop:disable Metrics/CyclomaticComplexity
        def self.json_sort_key(element)
          case element
          when true, false then [1, element ? 1 : 0]
          when ::Numeric then [2, element]
          when ::String then [3, element]
          when ::Array then [4, element.map { |item| json_sort_key(item) }]
          when ::Hash then [5, element.keys.sort.map { |key| [key, json_sort_key(element[key])] }]
          else [0, 0] # null
          end
        end
        # rubocop:enable Metrics/CyclomaticComplexity
        private_class_method :json_sort_key
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength

Ruby::Rego::Builtins::Codecs.register!
