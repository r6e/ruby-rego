# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "../errors"
require_relative "../value"
require_relative "collections/array_ops"
require_relative "collections/object_ops"
require_relative "collections/set_ops"

module Ruby
  module Rego
    module Builtins
      # Built-in collection helpers.
      module Collections
        extend RegistryHelpers

        MISSING_SET_ARGUMENT = Object.new.freeze

        COLLECTION_FUNCTIONS = {
          "set" => { arity: [0, 1], handler: :set },
          "sort" => { arity: 1, handler: :sort },
          "array.concat" => { arity: 2, handler: :array_concat },
          "array.slice" => { arity: 3, handler: :array_slice },
          "object.get" => { arity: 3, handler: :object_get },
          "object.keys" => { arity: 1, handler: :object_keys },
          "object.remove" => { arity: 2, handler: :object_remove },
          "union" => { arity: 2, handler: :union },
          "intersection" => { arity: 2, handler: :intersection },
          "set_diff" => { arity: 2, handler: :set_diff }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance

          register_configured_functions(registry, COLLECTION_FUNCTIONS)

          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param array [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        def self.sort(array)
          ArrayOps.sort(array)
        end

        # @param value [Ruby::Rego::Value, nil]
        # @return [Ruby::Rego::SetValue]
        def self.set(value = MISSING_SET_ARGUMENT)
          return SetValue.new([]) if value.equal?(MISSING_SET_ARGUMENT)

          Base.assert_type(value, expected: [ArrayValue, SetValue], context: "set")
          return value if value.is_a?(SetValue)

          SetValue.new(value.value)
        end

        # @param left [Ruby::Rego::Value]
        # @param right [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        def self.array_concat(left, right)
          ArrayOps.array_concat(left, right)
        end

        # @param array [Ruby::Rego::Value]
        # @param start [Ruby::Rego::Value]
        # @param stop [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        def self.array_slice(array, start, stop)
          ArrayOps.array_slice(array, start, stop)
        end

        # @param object [Ruby::Rego::Value]
        # @param key [Ruby::Rego::Value]
        # @param default [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        def self.object_get(object, key, default)
          ObjectOps.object_get(object, key, default)
        end

        # @param object [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        def self.object_keys(object)
          ObjectOps.object_keys(object)
        end

        # @param object [Ruby::Rego::Value]
        # @param keys [Ruby::Rego::Value]
        # @return [Ruby::Rego::ObjectValue]
        def self.object_remove(object, keys)
          ObjectOps.object_remove(object, keys)
        end

        # @param left [Ruby::Rego::Value]
        # @param right [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        def self.union(left, right)
          return SetOps.union_sets(left, right) if left.is_a?(SetValue) && right.is_a?(SetValue)
          return ObjectOps.union_objects(left, right) if left.is_a?(ObjectValue) && right.is_a?(ObjectValue)

          raise_union_type_error(left, right)
        end

        # @param left [Ruby::Rego::Value]
        # @param right [Ruby::Rego::Value]
        # @return [Ruby::Rego::SetValue]
        def self.intersection(left, right)
          SetOps.intersection(left, right)
        end

        # @param left [Ruby::Rego::Value]
        # @param right [Ruby::Rego::Value]
        # @return [Ruby::Rego::SetValue]
        def self.set_diff(left, right)
          SetOps.set_diff(left, right)
        end

        def self.raise_union_type_error(left, right)
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Type mismatch",
            expected: "both sets or both objects",
            actual: "#{left.class.name} and #{right.class.name}",
            context: "union",
            location: nil
          )
        end
        private_class_method :raise_union_type_error
      end
    end
  end
end

Ruby::Rego::Builtins::Collections.register!
