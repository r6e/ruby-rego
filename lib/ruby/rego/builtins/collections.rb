# frozen_string_literal: true

require_relative "base"
require_relative "registry"
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
        COLLECTION_FUNCTIONS = {
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

          COLLECTION_FUNCTIONS.each do |name, config|
            register_function(registry, name, config)
          end

          registry
        end

        def self.register_function(registry, name, config)
          return if registry.registered?(name)

          registry.register(name, config.fetch(:arity)) do |*args|
            public_send(config.fetch(:handler), *args)
          end
        end
        private_class_method :register_function

        # @param array [Ruby::Rego::Value]
        # @return [Ruby::Rego::ArrayValue]
        def self.sort(array)
          ArrayOps.sort(array)
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
          raise Ruby::Rego::TypeError.new(
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
