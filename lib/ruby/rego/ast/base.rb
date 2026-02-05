# frozen_string_literal: true

module Ruby
  module Rego
    module AST
      # Base class for all AST nodes.
      #
      # Provides location tracking, a visitor entry point, and common debugging
      # helpers.
      class Base
        # @param location [Location, nil]
        def initialize(location: nil)
          @location = location
        end

        # @return [Location, nil]
        attr_reader :location

        # @param visitor [Object]
        # @return [Object]
        def accept(visitor)
          visitor.visit(self)
        end

        # @param keys [Array<Symbol>, nil]
        # @return [Hash<Symbol, Object>]
        def deconstruct_keys(keys)
          attributes = deconstruct_attributes
          allowed = deconstructable_keys
          filtered = attributes.slice(*allowed)
          keys ? filtered.slice(*keys) : filtered
        end

        def deconstruct_attributes
          attributes = {} # @type var attributes: Hash[Symbol, Object]
          instance_variables.each_with_object(attributes) do |variable, result|
            key = variable.to_s.delete_prefix("@").to_sym
            result[key] = instance_variable_get(variable)
          end
          attributes
        end

        def deconstructable_keys
          instance_variables.map { |variable| variable.to_s.delete_prefix("@").to_sym }
        end

        private :deconstruct_attributes, :deconstructable_keys

        # @return [String]
        def to_s
          klass = self.class
          attributes = instance_variables.sort.map do |variable|
            value = instance_variable_get(variable)
            "#{variable.to_s.delete_prefix("@")}=#{klass.format_value(value)}"
          end

          "#{klass.name}(#{attributes.join(", ")})"
        end

        # @param other [Object]
        # @return [Boolean]
        def ==(other)
          return false unless other.instance_of?(self.class)

          instance_variables.sort.all? do |variable|
            instance_variable_get(variable) == other.instance_variable_get(variable)
          end
        end

        # @param other [Object]
        # @return [Boolean]
        def eql?(other)
          self == other
        end

        # @return [Integer]
        def hash
          values = instance_variables.sort.map { |variable| instance_variable_get(variable) }
          [self.class, values].hash
        end

        # @param value [Object]
        # @return [String]
        def self.format_value(value)
          case value
          when String, Symbol, Numeric, Array, Hash, TrueClass, FalseClass, NilClass
            value.inspect
          else
            value.to_s
          end
        end
      end
    end
  end
end
