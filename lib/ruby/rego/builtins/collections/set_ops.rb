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
            set_operation(left, right, name: "intersection") { |left_set, right_set| left_set & right_set }
          end

          # @param left [Ruby::Rego::Value]
          # @param right [Ruby::Rego::Value]
          # @return [Ruby::Rego::SetValue]
          def self.set_diff(left, right)
            set_operation(left, right, name: "set_diff") { |left_set, right_set| left_set - right_set }
          end

          # @param left [Ruby::Rego::Value]
          # @param right [Ruby::Rego::Value]
          # @return [Ruby::Rego::SetValue]
          def self.union_sets(left, right)
            set_operation(left, right, name: "union") { |left_set, right_set| left_set | right_set }
          end

          def self.set_operation(left, right, name:)
            left_set = set_contents(left, name: "#{name} left")
            right_set = set_contents(right, name: "#{name} right")
            SetValue.new(yield(left_set, right_set))
          end
          private_class_method :set_operation

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
