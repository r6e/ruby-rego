# frozen_string_literal: true

require_relative "../../../go_number_format"

module Ruby
  module Rego
    module Builtins
      module Yaml
        # Go strconv 'g' float formatting (FormatFloat(f, 'g', -1, 64)) for the YAML scalar emitter,
        # delegating the shortest-digit rendering to the shared {Ruby::Rego::GoNumberFormat} (the same
        # Go-'g' renderer the arbitrary-precision Number uses). Keeps the finite/zero handling the YAML
        # emitter needs. float_string stays public because ScalarResolver calls it.
        module Emitter
          # Go strconv.FormatFloat(f, 'g', -1, 64): shortest digits, scientific when the decimal
          # exponent is < -4 or >= 6 (handled by GoNumberFormat).
          # @return [String]
          def self.float_string(float)
            raise MarshalError, "non-finite number" unless float.finite?
            return float.to_s.start_with?("-") ? "-0" : "0" if float.zero?

            digits, point = GoNumberFormat.shortest_digits(float.to_s)
            GoNumberFormat.render(digits, point, float.negative?)
          end
        end
      end
    end
  end
end
