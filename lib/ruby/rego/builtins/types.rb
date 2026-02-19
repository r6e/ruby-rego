# frozen_string_literal: true

# rubocop:disable Naming/PredicatePrefix

require_relative "base"
require_relative "registry"

module Ruby
  module Rego
    module Builtins
      # Built-in type predicates.
      module Types
        TYPE_PREDICATES = {
          "is_string" => :is_string,
          "is_number" => :is_number,
          "is_boolean" => :is_boolean,
          "is_array" => :is_array,
          "is_object" => :is_object,
          "is_set" => :is_set,
          "is_null" => :is_null
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance

          TYPE_PREDICATES.each do |name, handler|
            register_predicate(registry, name, handler)
          end
          register_type_name(registry)

          registry
        end

        def self.register_predicate(registry, name, handler)
          return if registry.registered?(name)

          registry.register(name, 1) { |value| public_send(handler, value) }
        end
        private_class_method :register_predicate

        def self.register_type_name(registry)
          return if registry.registered?("type_name")

          registry.register("type_name", 1) { |value| type_name(value) }
        end
        private_class_method :register_type_name

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.is_string(value)
          BooleanValue.new(value.is_a?(StringValue))
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.is_number(value)
          BooleanValue.new(value.is_a?(NumberValue))
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.is_boolean(value)
          BooleanValue.new(value.is_a?(BooleanValue))
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.is_array(value)
          BooleanValue.new(value.is_a?(ArrayValue))
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.is_object(value)
          BooleanValue.new(value.is_a?(ObjectValue))
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.is_set(value)
          BooleanValue.new(value.is_a?(SetValue))
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.is_null(value)
          BooleanValue.new(value.is_a?(NullValue))
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.type_name(value)
          StringValue.new(value.type_name)
        end
      end
    end
  end
end

Ruby::Rego::Builtins::Types.register!

# rubocop:enable Naming/PredicatePrefix
