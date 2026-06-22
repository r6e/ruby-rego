# frozen_string_literal: true

# rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength

require "psych"
require_relative "../term_order"

module Ruby
  module Rego
    module Builtins
      module Yaml
        # Builds a Psych node tree and emits it, matching OPA's yaml.marshal byte-for-byte.
        #
        # Layout, folding, escaping, and the plain→single/double downgrade are delegated
        # to Psych (libyaml — the engine gopkg.in/yaml.v2 ports), so they match for free.
        # This module supplies only what diverges from Psych's defaults: object keys are
        # sorted, floats use Go's strconv 'g' (shortest, eprec=6) formatting, nil emits as
        # `null`, and scalar styles are set explicitly (DOUBLE for type-ambiguous strings).
        # Key comparison and float formatting live in emitter/{key_order,float_format}.rb,
        # required at the bottom.
        module Emitter
          # Raised when a value cannot be marshaled (e.g. a non-finite number).
          class MarshalError < StandardError; end

          PLAIN = Psych::Nodes::Scalar::PLAIN
          DOUBLE = Psych::Nodes::Scalar::DOUBLE_QUOTED
          LITERAL = Psych::Nodes::Scalar::LITERAL
          # ANY lets libyaml auto-pick plain/single/double exactly as yaml.v2's libyaml
          # does — so the structural quote choice matches OPA for free.
          AUTO = Psych::Nodes::Scalar::ANY
          BLOCK_SEQ = Psych::Nodes::Sequence::BLOCK
          BLOCK_MAP = Psych::Nodes::Mapping::BLOCK

          # yaml.v2 quotes strings that would otherwise resolve to a timestamp or a
          # base-60 number (the latter dropped from resolution but still quoted out).
          TIMESTAMP = /\A\d{4}-\d{1,2}-\d{1,2}([Tt ]\d{1,2}:\d{1,2}:\d{1,2}(\.\d+)?([Zz]|[+-]\d{1,2}(:\d{2})?)?)?\z/
          BASE60 = /\A[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9_]*)?\z/

          # @param ruby [Object] a JSON-compatible Ruby value
          # @return [String]
          def self.emit(ruby)
            document = Psych::Nodes::Document.new([], [], true)
            document.implicit_end = true
            document.children << build_node(ruby)
            stream = Psych::Nodes::Stream.new
            stream.children << document
            stream.to_yaml
          rescue Psych::Exception => e
            raise MarshalError, e.message
          end

          # @return [Psych::Nodes::Node]
          def self.build_node(ruby)
            case ruby
            when nil then scalar("null", PLAIN)
            when true then scalar("true", PLAIN)
            when false then scalar("false", PLAIN)
            when Integer then scalar(ruby.to_s, PLAIN)
            when Float then scalar(float_string(ruby), PLAIN)
            # OPA's yaml.marshal routes a number through Go float64, so a Number renders exactly like
            # the equivalent Float (1.50 -> 1.5, 2.0 -> 2, 1e308 -> 1e+308); a magnitude beyond float64
            # range becomes non-finite and raises MarshalError -> undefined, as it did pre-Number.
            when Number then scalar(float_string(ruby.to_f), PLAIN)
            when String then string_scalar(ruby)
            when Symbol then string_scalar(ruby.to_s)
            when Array then sequence(ruby)
            when Set then sequence(TermOrder.sorted(ruby))
            when Hash then mapping(ruby)
            else raise MarshalError, "unsupported type #{ruby.class}"
            end
          end
          private_class_method :build_node

          # Emits a string scalar, first replacing invalid UTF-8 with U+FFFD (as OPA's
          # JSON round-trip does) so libyaml never rejects the bytes.
          # @return [Psych::Nodes::Scalar]
          def self.string_scalar(string)
            clean = sanitize(string)
            scalar(clean, string_style(clean))
          end
          private_class_method :string_scalar

          # @return [String]
          def self.sanitize(string)
            return string if string.encoding == Encoding::UTF_8 && string.valid_encoding?

            string.dup.force_encoding(Encoding::UTF_8).scrub("�")
          end
          private_class_method :sanitize

          # Builds a scalar node. PLAIN/DOUBLE force that style; AUTO sets both implicit
          # flags so libyaml picks plain/single/double/literal itself (no `!` tag).
          # @return [Psych::Nodes::Scalar]
          def self.scalar(value, style)
            case style
            when PLAIN then Psych::Nodes::Scalar.new(value, nil, nil, true, false, PLAIN)
            when DOUBLE then Psych::Nodes::Scalar.new(value, nil, nil, false, true, DOUBLE)
            when LITERAL then Psych::Nodes::Scalar.new(value, nil, nil, false, true, LITERAL)
            else Psych::Nodes::Scalar.new(value, nil, nil, true, true, AUTO)
            end
          end
          private_class_method :scalar

          # Force DOUBLE only where yaml.v2 must quote to preserve a string: empty, or a
          # value that would resolve to a non-string / timestamp / base-60. Otherwise AUTO
          # lets libyaml make the same plain/single/double/literal choice OPA does.
          # @return [Integer]
          def self.string_style(string)
            return DOUBLE if string.empty? || ScalarResolver.ambiguous?(string)
            return DOUBLE if TIMESTAMP.match?(string) || BASE60.match?(string)
            return LITERAL if string.include?("\n")

            AUTO
          end
          private_class_method :string_style

          # @return [Psych::Nodes::Sequence]
          def self.sequence(array)
            node = Psych::Nodes::Sequence.new(nil, nil, true, BLOCK_SEQ)
            array.each { |item| node.children << build_node(item) }
            node
          end
          private_class_method :sequence

          # OPA stringifies object keys, then yaml.v2 sorts them with its `keyList` natural
          # order (digit runs compared numerically, so "item2" < "item10" and "2" < "10"),
          # not lexicographically. A non-string Rego key is valid, so build each value from
          # its own entry.
          # @return [Psych::Nodes::Mapping]
          def self.mapping(hash)
            node = Psych::Nodes::Mapping.new(nil, nil, true, BLOCK_MAP)
            hash.map { |key, value| [key_string(key), value] }
                .sort { |left, right| natural_compare(left.first, right.first) }
                .each do |string_key, value|
                  node.children << scalar(string_key, string_style(string_key))
                  node.children << build_node(value)
                end
            node
          end
          private_class_method :mapping

          # The string form of an object key (mirrors how OPA stringifies map keys).
          # @return [String]
          def self.key_string(key)
            case key
            when String then sanitize(key)
            when Float then float_string(key)
            when Number then float_string(key.to_f)
            when true then "true"
            when false then "false"
            when nil then "null"
            else key.to_s
            end
          end
          private_class_method :key_string
        end
      end
    end
  end
end

require_relative "emitter/key_order"
require_relative "emitter/float_format"
# rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength
