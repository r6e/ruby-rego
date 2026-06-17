# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Yaml
        # Explicit core-schema tag coercion (!!int/!!float/!!bool/!!null/!!binary). A tagged
        # scalar is coerced to that type, erroring on a value that can't be coerced (like OPA).
        # Lives apart from the resolution core so the main file stays under RubyCritic's
        # complexity budget; helpers (parse_integer, json_number, ...) resolve via self-dispatch.
        module ScalarResolver
          # @return [Object]
          def self.tag_coerce(type, value)
            case type
            when "int" then tag_int(value)
            when "float" then tag_float(value)
            when "bool" then tag_bool(value)
            when "null" then tag_null(value)
            when "binary" then tag_binary(value)
            # !!str — and any unrecognized core tag (e.g. !!timestamp) — yields the raw string.
            else value
            end
          end
          private_class_method :tag_coerce

          # @return [Integer]
          def self.tag_int(value)
            parse_integer(value.delete("_")) || raise(ResolveError, "invalid !!int")
          end
          private_class_method :tag_int

          # @return [Float, Integer]
          def self.tag_float(value)
            mapped = RESOLVE_MAP[value]
            return mapped if mapped.is_a?(Float) # .inf / .nan

            plain = value.delete("_")
            raise ResolveError, "invalid !!float" unless FLOAT_RE.match?(plain)

            json_number(float_value(plain) || raise(ResolveError, "invalid !!float"))
          end
          private_class_method :tag_float

          # base64 (yaml.v2 emits it wrapped, so whitespace is stripped). A pathologically
          # malformed payload yields undefined; OPA's leniency for some non-base64 bytes is
          # an unreproduced edge.
          # @return [String]
          def self.tag_binary(value)
            value.gsub(/\s/, "").unpack1("m0")
          rescue ArgumentError
            raise ResolveError, "invalid !!binary"
          end
          private_class_method :tag_binary

          # @return [bool]
          def self.tag_bool(value)
            mapped = RESOLVE_MAP[value]
            return mapped if [true, false].include?(mapped)

            raise ResolveError, "invalid !!bool"
          end
          private_class_method :tag_bool

          # @return [nil]
          def self.tag_null(value)
            return nil if RESOLVE_MAP.key?(value) && RESOLVE_MAP[value].nil?

            raise ResolveError, "invalid !!null"
          end
          private_class_method :tag_null
        end
      end
    end
  end
end
