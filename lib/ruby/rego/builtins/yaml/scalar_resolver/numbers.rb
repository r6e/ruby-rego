# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Yaml
        # Plain-scalar number resolution (yaml.v2 resolveTable + Go strconv parsing).
        # Lives apart from the resolution core so the main file stays under RubyCritic's
        # complexity budget. Constants (RESOLVE_MAP, FLOAT_RE, ...) live in the main module
        # body and resolve here via lexical scope, since this file loads after it.
        module ScalarResolver
          # @return [Integer, Float, nil]
          def self.numeric(string)
            plain = string.delete("_")
            integer = parse_integer(plain)
            return integer if integer
            return nil unless FLOAT_RE.match?(plain)

            float = float_value(plain)
            # An overflow to ±Inf is not a number in go-yaml — it falls back to its string
            # text (1e999 -> "1e999"). An underflow is a finite 0.0 and stays the number 0.
            # (The !!float tag path in tags.rb undefines an overflow by raising directly, as
            # OPA does — it demands a float and has no string fallback.)
            return nil unless float&.finite?

            json_number(float)
          end
          private_class_method :numeric

          # Parses a FLOAT_RE-matched scalar. Dot-edge forms (".5", "5.", "5.e3") are
          # normalized to have a digit on both sides of the point so Ruby's Float accepts
          # them on every supported version — Ruby < 3.4 rejects a bare leading/trailing
          # dot, unlike Go's strconv (which OPA uses).
          # @return [Float, nil]
          def self.float_value(plain)
            normalized = plain.sub(/\A(?<sign>[+-]?)\./, '\k<sign>0.').sub(/\.(?=[eE]|\z)/, ".0")
            Float(normalized, exception: false)
          end
          private_class_method :float_value

          # OPA's YAML→JSON round-trip renders an integer-valued float without a decimal
          # (Go json uses fixed notation for 1e-6 <= |x| < 1e21), so it reparses as an
          # integer. Mirror that so e.g. "1.0"/"1e10" unmarshal to integers, not floats.
          # @return [Integer, Float]
          def self.json_number(float)
            # Defense-in-depth: every caller already pre-filters non-finite (numeric returns
            # nil, tag_float raises, float_from_int only passes finite values), so this guard is
            # currently unreachable — but it must stay, since float.to_i below raises
            # FloatDomainError on ±Inf. Pass non-finite through untouched if it ever arrives.
            return float unless float.finite?
            return 0 if float.zero?
            return float.to_i if float == float.to_i && float.abs >= 1e-6 && float.abs < 1e21

            float
          end
          private_class_method :json_number

          # Go strconv.ParseInt base 0: 0x hex, 0o/leading-zero octal, 0b binary, decimal.
          # A prefixed (0x/0o/0b) literal outside go-yaml's accepted range returns nil so the
          # resolver falls back to its string text. A bare decimal / leading-zero octal WITHIN
          # float64 range is left uncapped: `numeric` returns its exact bignum directly (go-yaml
          # instead reparses it as a lossy float64 — a deferred output-formatting divergence).
          # ABOVE float64 max, decimal_overflows_float64? caps it to nil (it is a string in
          # go-yaml, never a number), which also bounds the bignum parse cost.
          # @return [Integer, nil]
          def self.parse_integer(string)
            sign, digits = split_sign(string)
            base, body, prefixed = integer_base(digits)
            return nil if body.empty?
            # Reject a float64-overflowing decimal before Integer() materializes a multi-
            # megabyte bignum — bounding parse cost the way go-yaml's fixed-width strconv does.
            return nil if !prefixed && decimal_overflows_float64?(string)

            value = Integer(body, base, exception: false)
            return nil unless value

            signed = sign * value
            return nil if prefixed && !go_int_range?(signed, signed: explicitly_signed?(string))

            signed
          end
          private_class_method :parse_integer

          # go-yaml dispatches numeric coercion on a scalar's first byte (yaml.v2 resolveTable):
          # only a sign, digit, or dot opens the number path. The plain path gates on this in
          # `resolve`; the !!int/!!float tag paths gate too, BEFORE stripping underscores, so a
          # leading-underscore token (which go-yaml leaves a string -> tag mismatch -> undefined)
          # is not wrongly coerced once its separators are removed.
          # @return [bool]
          def self.numeric_lead?(value)
            # value[0].to_s: empty? guards against "", but String#[] is typed nilable, so .to_s
            # keeps steep happy (nil never actually reaches it).
            !value.empty? && NUMBER_LEADS.include?(value[0].to_s)
          end
          private_class_method :numeric_lead?

          # An explicit leading +/- means strconv.ParseUint rejects the token, so the value is
          # int64-bounded (see the INT64/UINT64 constant block). Callers strip underscores first.
          # @return [bool]
          def self.explicitly_signed?(text)
            text.start_with?("+", "-")
          end
          private_class_method :explicitly_signed?

          # Whether `text` parses as a decimal that overflows float64 to ±Inf — go-yaml's
          # ParseFloat ceiling, above which a plain / leading-octal scalar is a string (or an
          # !!int is undefined), not a number. A non-decimal body (e.g. 0x… hex) yields nil
          # from Float() and is treated as non-overflowing (its range is checked separately).
          # @return [bool]
          def self.decimal_overflows_float64?(text)
            value = Float(text, exception: false)
            !value.nil? && !value.finite?
          end
          private_class_method :decimal_overflows_float64?

          # Whether a parsed integer is one go-yaml accepts (the range a prefixed 0x/0o/0b
          # scalar must fit before falling back to a string, and the range an !!int requires).
          # Sign-aware per the ParseInt/ParseUint rule on the INT64/UINT64 constant block.
          # @return [bool]
          def self.go_int_range?(value, signed:)
            value.between?(INT64_MIN, signed ? INT64_MAX : UINT64_MAX)
          end
          private_class_method :go_int_range?

          # The positive uint64-only magnitude band: above int64 max, up to uint64 max. An
          # UNSIGNED value here decodes to a Go uint64 — which has no !!float coercion and no
          # JSON object-key case. Callers supply the signedness/origin distinction.
          # @return [bool]
          def self.uint64_band?(value)
            value > INT64_MAX && value <= UINT64_MAX
          end
          private_class_method :uint64_band?

          # @return [Array(Integer, String)]
          def self.split_sign(string)
            return [-1, string[1..] || ""] if string.start_with?("-")
            return [1, string[1..] || ""] if string.start_with?("+")

            [1, string]
          end
          private_class_method :split_sign

          # Returns [base, body, prefixed?]. `prefixed?` marks an explicit 0x/0o/0b form
          # (capped to int64/uint64) apart from a bare decimal / leading-zero octal (uncapped).
          # @return [Array(Integer, String, bool)]
          def self.integer_base(digits)
            case digits
            when /\A0[xX][0-9a-fA-F]+\z/ then [16, digits[2..].to_s, true]
            when /\A0[oO][0-7]+\z/ then [8, digits[2..].to_s, true]
            when /\A0[bB][01]+\z/ then [2, digits[2..].to_s, true]
            when /\A0[0-7]+\z/ then [8, digits[1..].to_s, false]
            else [10, digits, false]
            end
          end
          private_class_method :integer_base
        end
      end
    end
  end
end
