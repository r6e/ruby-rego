# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in encoding/decoding helpers.
      module Codecs
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
      end
    end
  end
end
