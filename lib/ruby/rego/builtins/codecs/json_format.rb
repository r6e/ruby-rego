# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in encoding/decoding helpers.
      module Codecs
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
