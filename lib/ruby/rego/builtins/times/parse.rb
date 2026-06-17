# frozen_string_literal: true

require_relative "go_layout/parser"

module Ruby
  module Rego
    module Builtins
      # time.parse_ns: parse a timestamp `value` according to a Go reference-time `layout`,
      # returning nanoseconds since the Unix epoch (the inverse of time.format), matching OPA.
      # The actual port of Go's time.Parse lives in GoLayout (times/go_layout/parser.rb); this
      # reopens Times only to register the builtin and adapt its argument/undefined handling.
      module Times
        # @param layout_value [Ruby::Rego::Value] a Go reference-time layout (or a named layout)
        # @param value_value [Ruby::Rego::Value] the timestamp text to parse
        # @return [Integer, Ruby::Rego::UndefinedValue] epoch nanoseconds, or undefined when the
        #   value does not match the layout, a field is out of range, input is left over, or the
        #   instant falls outside the int64-nanosecond range
        def self.parse_ns(layout_value, value_value)
          layout = string_arg(layout_value, "time.parse_ns")
          value = string_arg(value_value, "time.parse_ns")
          # parse returns the ns Integer (0 is valid and truthy) or nil → undefined.
          GoLayout.parse(layout, value) || UndefinedValue.new
        end
      end
    end
  end
end
