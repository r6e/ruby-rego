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

          # True when `sub` is a subset of `super`, matching OPA's object.subset. Valid operand
          # pairs: object/object (recursive), set/set, array/array (a contiguous subslice), and
          # array/set (super array contains the set's members). Any other pairing is undefined.
          # @param super_value [Ruby::Rego::Value]
          # @param sub_value [Ruby::Rego::Value]
          # @return [Ruby::Rego::BooleanValue]
          def self.subset(super_value, sub_value)
            BooleanValue.new(subset?(super_value.to_ruby, sub_value.to_ruby))
          end

          def self.subset?(sup, sub)
            return object_subset?(sup, sub) if both?(sup, sub, ::Hash)
            return set_subset?(sup, sub) if both?(sup, sub, ::Set)
            return array_subset?(sup, sub) if both?(sup, sub, ::Array)
            return array_set_subset?(sup, sub) if sup.is_a?(::Array) && sub.is_a?(::Set)

            Base.raise_argument_error(
              "object.subset arguments must be the same type, or an array and a set",
              expected: "matching collection types", actual: "mismatched", context: "object.subset"
            )
          end
          private_class_method :subset?

          def self.both?(left, right, type)
            left.is_a?(type) && right.is_a?(type)
          end
          private_class_method :both?

          # OPA set membership uses numeric equality (1 and 1.0 match), so this compares with `==`
          # rather than Ruby's Set#subset?/include? (which hash on eql?, treating 1 and 1.0 as
          # distinct). Note: the gem's SetValue itself does not yet dedup 1 and 1.0 — a separate
          # pre-existing gap — but membership-by-== still yields OPA's subset answer.
          def self.set_subset?(sup, sub)
            sub.all? { |element| member?(sup, element) }
          end
          private_class_method :set_subset?

          def self.member?(collection, value)
            collection.any? { |element| element == value }
          end
          private_class_method :member?

          # Every key in `sub` must be present in `super` with an equal value, recursing into
          # nested object/set/array values. Keys are matched by `==` (so a numeric `1` key
          # matches `1.0`, as OPA does), not by Ruby Hash lookup which hashes on eql?.
          def self.object_subset?(sup, sub)
            sub.all? { |key, sub_value| super_value_subset?(sup, key, sub_value) }
          end
          private_class_method :object_subset?

          # True when `super` has a key equal (by `==`) to `key` whose value contains `sub_value`.
          # :reek:ControlParameter
          def self.super_value_subset?(sup, key, sub_value)
            sup.any? { |super_key, super_value| super_key == key && nested_subset?(super_value, sub_value) }
          end
          private_class_method :super_value_subset?

          # Like #subset? for a nested value, but a mismatched-type pair is simply not a subset
          # (it does not raise) and only collection types recurse.
          def self.nested_subset?(sup, sub)
            return true if sup == sub
            return object_subset?(sup, sub) if both?(sup, sub, ::Hash)
            return set_subset?(sup, sub) if both?(sup, sub, ::Set)
            return array_subset?(sup, sub) if both?(sup, sub, ::Array)

            false
          end
          private_class_method :nested_subset?

          # `sub` must appear as a contiguous run within `super` (matching OPA). An empty `sub`
          # is a subslice of anything.
          def self.array_subset?(sup, sub)
            return true if sub.empty?

            length = sub.length
            return false if length > sup.length

            sup.each_cons(length).any?(sub.method(:==))
          end
          private_class_method :array_subset?

          # True once `super`'s elements have covered every member of the set `sub` (OPA counts
          # super positions whose element is in sub until the set is exhausted).
          def self.array_set_subset?(sup, sub)
            unique = unique_members(sub)
            unmatched = unique.size
            sup.each do |element|
              unmatched -= 1 if member?(unique, element)
              return true if unmatched.zero?
            end
            false
          end
          private_class_method :array_set_subset?

          # The set's members de-duplicated under `==` (so 1 and 1.0 collapse), giving OPA's
          # set cardinality even though the gem's SetValue does not yet normalise them.
          def self.unique_members(collection)
            unique = [] # @type var unique: Array[untyped]
            collection.each { |element| unique << element unless member?(unique, element) }
            unique
          end
          private_class_method :unique_members

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
          # when both sides hold objects (mirrors OPA's object.union). Object keys
          # are arbitrary scalars (Rego allows non-string keys), not only strings.
          #
          # @param left [Hash{Object => Ruby::Rego::Value}]
          # @param right [Hash{Object => Ruby::Rego::Value}]
          # @return [Hash{Object => Ruby::Rego::Value}]
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
