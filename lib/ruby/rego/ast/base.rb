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
