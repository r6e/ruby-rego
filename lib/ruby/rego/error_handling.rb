# frozen_string_literal: true

require_relative "errors"
require_relative "location"

module Ruby
  # Ruby Rego implementation namespace.
  module Rego
    # Internal helper for wrapping unexpected errors in public API calls.
    module ErrorHandling
      # @param context [String]
      # @yieldreturn [Object]
      # @return [Object]
      # :reek:TooManyStatements
      # :reek:UncommunicativeVariableName
      def self.wrap(context)
        yield
      rescue Error => e
        raise e
      rescue StandardError => e
        raise build_error(context, e), cause: e
      end

      # @param error [Object]
      # @return [Location, nil]
      # :reek:ManualDispatch
      # :reek:TooManyStatements
      def self.location_from(error)
        location = error.respond_to?(:location) ? error.location : nil
        return location if location

        line = error.respond_to?(:line) ? error.line : nil
        column = error.respond_to?(:column) ? error.column : nil

        return Location.new(line: line, column: column) if line.is_a?(Integer) && column.is_a?(Integer)

        nil
      end

      # @param context [String]
      # @param error [StandardError]
      # @return [Error]
      def self.build_error(context, error)
        Error.new("Rego #{context} failed: #{error.message}", location: location_from(error))
      end

      private_class_method :build_error
    end

    private_constant :ErrorHandling
  end
end
