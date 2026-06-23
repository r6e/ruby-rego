# frozen_string_literal: true

require_relative "../term_order"

module Ruby
  module Rego
    module Builtins
      # Built-in encoding/decoding helpers.
      module Codecs
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
        # rubocop:disable Metrics/CyclomaticComplexity -- a recursive type-dispatch over JSON shapes plus
        # the undefined-propagation guard; each arm is one shape, not branching logic to decompose.
        def self.jsonify(ruby)
          # An undefined sentinel inside a collection (e.g. a number beyond Float range read from input,
          # which the value layer maps to undefined) makes the marshal undefined, as in OPA where
          # undefined propagates. ArgumentError is caught by canonical_json and mapped to undefined.
          raise ::ArgumentError, "cannot marshal undefined" if ruby.equal?(UndefinedValue::UNDEFINED)

          case ruby
          when ::Hash then ruby.keys.sort_by(&:to_s).to_h { |key| [key.to_s, jsonify(ruby[key])] }
          when ::Set then sorted_json_array(ruby)
          when ::Array then ruby.map { |element| jsonify(element) }
          else ruby
          end
        end
        # rubocop:enable Metrics/CyclomaticComplexity
        private_class_method :jsonify

        # Sorts the raw set elements into OPA's term order (so a nested set ranks as a set,
        # above an object — which jsonify would otherwise flatten to an array) before
        # converting each to its JSON form.
        #
        # @param set [Set]
        # @return [Array<Object>]
        def self.sorted_json_array(set)
          TermOrder.sorted(set).map { |element| jsonify(element) }
        end
        private_class_method :sorted_json_array
      end
    end
  end
end
