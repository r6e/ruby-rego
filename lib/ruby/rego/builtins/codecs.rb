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
          "base64url.encode" => { arity: 1, handler: :base64url_encode },
          "base64url.decode" => { arity: 1, handler: :base64url_decode },
          "hex.encode" => { arity: 1, handler: :hex_encode },
          "hex.decode" => { arity: 1, handler: :hex_decode },
          "urlquery.encode" => { arity: 1, handler: :urlquery_encode },
          "urlquery.decode" => { arity: 1, handler: :urlquery_decode }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, CODEC_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # Compact JSON with object keys sorted and sets rendered as sorted arrays,
        # matching OPA's json.marshal output.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.json_marshal(value)
          StringValue.new(JSON.generate(jsonify(value.to_ruby)))
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

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.urlquery_decode(value)
          StringValue.new(CGI.unescape(string_arg(value, "urlquery.decode")))
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
        rescue ArgumentError, JSON::ParserError => e
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

        # Deterministic sort key mirroring OPA's set ordering (by type, then value).
        #
        # @param element [Object]
        # @return [Array<Object>]
        def self.json_sort_key(element)
          case element
          when true, false then [1, element ? 1 : 0]
          when ::Numeric then [2, element]
          when ::String then [3, element]
          when ::Array, ::Hash then [4, JSON.generate(element)]
          else [0, 0] # null
          end
        end
        private_class_method :json_sort_key
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength

Ruby::Rego::Builtins::Codecs.register!
