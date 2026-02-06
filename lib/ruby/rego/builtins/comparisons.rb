# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "../value"
require_relative "comparisons/casts"

module Ruby
  module Rego
    module Builtins
      # Built-in comparison and casting helpers.
      module Comparisons
        extend RegistryHelpers

        COMPARISON_FUNCTIONS = {
          "equal" => { arity: 2, handler: :equal },
          "to_number" => { arity: 1, handler: :to_number },
          "cast_string" => { arity: 1, handler: :cast_string },
          "cast_boolean" => { arity: 1, handler: :cast_boolean },
          "cast_array" => { arity: 1, handler: :cast_array },
          "cast_set" => { arity: 1, handler: :cast_set },
          "cast_object" => { arity: 1, handler: :cast_object }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance

          register_configured_functions(registry, COMPARISON_FUNCTIONS)

          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param left [Ruby::Rego::Value]
        # @param right [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.equal(left, right)
          BooleanValue.new(left == right)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.to_number(value)
          Casts.to_number(value)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.cast_string(value)
          Casts.cast_string(value)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.cast_boolean(value)
          Casts.cast_boolean(value)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        def self.cast_array(value)
          Casts.cast_array(value)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::SetValue]
        def self.cast_set(value)
          Casts.cast_set(value)
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::ObjectValue]
        def self.cast_object(value)
          Casts.cast_object(value)
        end
      end
    end
  end
end

Ruby::Rego::Builtins::Comparisons.register!
