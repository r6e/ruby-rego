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

          # An !!int has no float/string fallback, so a value outside go-yaml's accepted
          # range is undefined (any base) — unlike a plain decimal, which becomes a lossy
          # float. The range is sign-aware: an explicitly +/- signed value must fit int64.
          # go_int_range? gates a bare-decimal / leading-octal value WITHIN float64 range that
          # exceeds uint64 max (parse_integer returns its exact bignum, which this rejects).
          # A float64-overflowing or prefixed-out-of-range value already short-circuits on
          # `integer` being nil (parse_integer caps those).
          # @return [Integer]
          def self.tag_int(value)
            raise ResolveError, "invalid !!int" unless numeric_lead?(value)

            stripped = value.delete("_")
            integer = parse_integer(stripped)
            return integer if integer && go_int_range?(integer, signed: explicitly_signed?(stripped))

            raise ResolveError, "invalid !!int"
          end
          private_class_method :tag_int

          # @return [Float, Integer]
          def self.tag_float(value)
            mapped = RESOLVE_MAP[value]
            return mapped if mapped.is_a?(Float) # .inf / .nan
            raise ResolveError, "invalid !!float" unless numeric_lead?(value)

            plain = value.delete("_")
            # go-yaml resolves an integer FIRST (ParseInt→ParseUint→ParseFloat) then float-coerces
            # it, so a 0x/0o/0b or decimal integer reaches !!float through the integer path, not
            # FLOAT_RE (which matches no prefixed base). A non-integer scalar falls through.
            integer = parse_integer(plain)
            return float_from_int(integer, plain) unless integer.nil?

            raise ResolveError, "invalid !!float" unless FLOAT_RE.match?(plain)

            float = float_value(plain) || raise(ResolveError, "invalid !!float")
            # A float64-overflowing !!float is undefined in EVERY position. Undefine it here
            # rather than emitting ±Inf for a downstream catch: the object-key path canonicalizes
            # a non-finite key to ".inf"/".nan" BEFORE reject_non_finite runs, which would leave an
            # overflow key wrongly defined (and mistaken for a genuine .inf literal).
            raise ResolveError, "invalid !!float" unless float.finite?

            json_number(float)
          end
          private_class_method :tag_float

          # Float-coerces an integer-resolved !!float value the way go-yaml does. An UNSIGNED
          # integer in the uint64-only band resolves as a Go uint64, for which !!float has no
          # coercion → undefined; every other integer (int64-range any base, or signed/over-uint64
          # that ParseFloat handles) becomes a float64 (lossy — a deferred output divergence).
          # @return [Float, Integer]
          def self.float_from_int(integer, plain)
            raise ResolveError, "uint64 !!float" if uint64_band?(integer) && !explicitly_signed?(plain)

            json_number(Float(integer))
          end
          private_class_method :float_from_int

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
