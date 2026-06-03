# frozen_string_literal: true

require_relative "../base"
require_relative "../../errors"
require_relative "../../value"

# rubocop:disable Metrics/ModuleLength
module Ruby
  module Rego
    module Builtins
      module Collections
        # Object-focused collection helpers.
        module ObjectOps
          # @param object [Ruby::Rego::Value]
          # @param key [Ruby::Rego::Value]
          # @param default [Ruby::Rego::Value]
          # @return [Ruby::Rego::Value]
          def self.object_get(object, key, default)
            obj = object_value(object, name: "object.get object")
            key_value = normalize_object_key(Base.to_ruby(key))
            value = obj.fetch_reference(key_value)
            value.is_a?(UndefinedValue) ? default : value
          end

          # @param object [Ruby::Rego::Value]
          # @return [Ruby::Rego::SetValue]
          def self.object_keys(object)
            obj = object_value(object, name: "object.keys")
            SetValue.new(obj.value.keys)
          end

          # @param object [Ruby::Rego::Value]
          # @param keys [Ruby::Rego::Value]
          # @return [Ruby::Rego::ObjectValue]
          def self.object_remove(object, keys)
            obj = object_value(object, name: "object.remove object")
            remove_keys = key_collection(keys, name: "object.remove keys")
            filtered = obj.value.reject { |key, _value| remove_keys.include?(normalize_object_key(key)) }
            ObjectValue.new(filtered)
          end

          # Deep-merges two objects with the second operand winning conflicts
          # (OPA's object.union). Nested objects merge recursively; any other
          # conflict or type mismatch takes the second operand's value.
          #
          # @param left [Ruby::Rego::Value]
          # @param right [Ruby::Rego::Value]
          # @return [Ruby::Rego::ObjectValue]
          def self.object_union(left, right)
            merged = deep_union(
              object_value(left, name: "object.union").value,
              object_value(right, name: "object.union").value
            )
            ObjectValue.new(merged)
          end

          # @param array [Ruby::Rego::Value]
          # @return [Ruby::Rego::ObjectValue]
          def self.object_union_n(array)
            Base.assert_type(array, expected: ArrayValue, context: "object.union_n")
            seed = {} # @type var seed: Hash[untyped, Value]
            merged = array.value.reduce(seed) do |acc, element|
              deep_union(acc, object_value(element, name: "object.union_n element").value)
            end
            ObjectValue.new(merged)
          end

          # @param object [Ruby::Rego::Value]
          # @param keys [Ruby::Rego::Value]
          # @return [Ruby::Rego::ObjectValue]
          def self.object_filter(object, keys)
            obj = object_value(object, name: "object.filter object")
            keep = key_collection(keys, name: "object.filter keys")
            ObjectValue.new(obj.value.select { |key, _value| keep.include?(normalize_object_key(key)) })
          end

          # Backs the polymorphic `union` builtin for two objects: a strict shallow
          # merge that RAISES on a conflicting key. Distinct from `object_union`
          # above (OPA's object.union), which is a deep merge where the right wins.
          #
          # @param left [Ruby::Rego::Value]
          # @param right [Ruby::Rego::Value]
          # @return [Ruby::Rego::ObjectValue]
          def self.union_objects(left, right)
            left_obj = object_value(left, name: "union left").value
            right_obj = object_value(right, name: "union right").value
            ObjectValue.new(merge_objects(left_obj, right_obj))
          end

          def self.object_value(value, name:)
            object = value # @type var object: ObjectValue
            Base.assert_type(object, expected: ObjectValue, context: name)
            object
          end
          private_class_method :object_value

          def self.normalize_object_key(key)
            key.is_a?(Symbol) ? key.to_s : key
          end
          private_class_method :normalize_object_key

          def self.key_collection(keys, name:)
            values = key_values(keys, name: name)
            Set.new(values.map { |key| normalize_object_key(Base.to_ruby(key)) })
          end
          private_class_method :key_collection

          def self.key_values(keys, name:)
            return array_key_values(keys) if keys.is_a?(ArrayValue)
            return values_from_set(keys) if keys.is_a?(SetValue)
            return keys.value.keys if keys.is_a?(ObjectValue)

            Base.assert_type(keys, expected: [ArrayValue, SetValue, ObjectValue], context: name)
            []
          end
          private_class_method :key_values

          # Deep-merges two key->Value hashes; the right hash wins, recursing only
          # when both sides hold objects (mirrors OPA's object.union).
          #
          # @param left [Hash{String => Ruby::Rego::Value}]
          # @param right [Hash{String => Ruby::Rego::Value}]
          # @return [Hash{String => Ruby::Rego::Value}]
          def self.deep_union(left, right)
            right.each_with_object(left.dup) do |(key, right_value), merged|
              merged[key] = merge_value(merged[key], right_value)
            end
          end
          private_class_method :deep_union

          # @param left_value [Ruby::Rego::Value, nil]
          # @param right_value [Ruby::Rego::Value]
          # @return [Ruby::Rego::Value]
          def self.merge_value(left_value, right_value)
            return right_value unless left_value.is_a?(ObjectValue) && right_value.is_a?(ObjectValue)

            ObjectValue.new(deep_union(left_value.value, right_value.value))
          end
          private_class_method :merge_value

          def self.array_key_values(keys)
            keys.value
          end
          private_class_method :array_key_values

          def self.values_from_set(keys)
            keys.value.to_a
          end
          private_class_method :values_from_set

          def self.merge_objects(left_obj, right_obj)
            conflict = conflicting_key(left_obj, right_obj)
            raise_object_conflict(conflict, left_obj, right_obj) if conflict

            left_obj.merge(right_obj)
          end
          private_class_method :merge_objects

          def self.conflicting_key(left_obj, right_obj)
            left_obj.each_key do |key|
              next unless right_obj.key?(key)
              next if left_obj[key] == right_obj[key]

              return key
            end
            nil
          end
          private_class_method :conflicting_key

          def self.raise_object_conflict(key, left_obj, right_obj)
            raise Ruby::Rego::BuiltinArgumentError.new(
              "Conflicting object keys",
              expected: "matching values for key #{key.inspect}",
              actual: [left_obj[key].to_ruby, right_obj[key].to_ruby],
              context: "union",
              location: nil
            )
          end
          private_class_method :raise_object_conflict
        end
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength
