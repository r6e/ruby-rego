# frozen_string_literal: true

require_relative "../base"
require_relative "../../errors"
require_relative "../../value"

module Ruby
  module Rego
    module Builtins
      module Collections
        # Set-focused collection helpers.
        module SetOps
          # @param left [Ruby::Rego::Value]
          # @param right [Ruby::Rego::Value]
          # @return [Ruby::Rego::SetValue]
          def self.intersection(left, right)
            left_set = set_contents(left, name: "intersection left")
            right_set = set_contents(right, name: "intersection right")
            SetValue.new(left_set & right_set)
          end

          # @param left [Ruby::Rego::Value]
          # @param right [Ruby::Rego::Value]
          # @return [Ruby::Rego::SetValue]
          def self.set_diff(left, right)
            left_set = set_contents(left, name: "set_diff left")
            right_set = set_contents(right, name: "set_diff right")
            SetValue.new(left_set - right_set)
          end

          # @param left [Ruby::Rego::Value]
          # @param right [Ruby::Rego::Value]
          # @return [Ruby::Rego::SetValue]
          def self.union_sets(left, right)
            left_set = set_contents(left, name: "union left")
            right_set = set_contents(right, name: "union right")
            SetValue.new(left_set | right_set)
          end

          def self.set_contents(value, name:)
            set_contents = value # @type var set_contents: SetValue
            Base.assert_type(set_contents, expected: SetValue, context: name)
            set_contents.value
          end
          private_class_method :set_contents
        end
      end
    end
  end
end
