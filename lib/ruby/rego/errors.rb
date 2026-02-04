# frozen_string_literal: true

require_relative "location"

module Ruby
  # Ruby Rego implementation namespace.
  module Rego
    # Shared formatting helpers for error message details.
    module ErrorFormatting
      def self.format_details(details)
        details.compact.map { |key, value| "#{key}: #{value}" }.join(", ")
      end
    end

    private_constant :ErrorFormatting

    # Base error for all Ruby::Rego exceptions.
    class Error < StandardError
      # @return [Location, nil]
      attr_reader :location

      # @param message [String, nil]
      # @param location [Location, nil]
      def initialize(message = nil, location: nil)
        @location = location
        super(compose_message(message))
      end

      private

      def compose_message(message)
        [message, location&.then { |loc| "(#{loc})" }].compact.join(" ")
      end
    end

    # Error raised during tokenization.
    class LexerError < Error
      # @return [Integer]
      attr_reader :line

      # @return [Integer]
      attr_reader :column

      # @param message [String]
      # @param line [Integer]
      # @param column [Integer]
      # @param offset [Integer, nil]
      # @param length [Integer, nil]
      def initialize(message, line:, column:, offset: nil, length: nil)
        @line = line
        @column = column
        location = Location.new(line: line, column: column, offset: offset, length: length)
        super(message, location: location)
      end
    end

    # Error raised during parsing.
    class ParserError < Error
      # @return [Integer]
      attr_reader :line

      # @return [Integer]
      attr_reader :column

      # @return [String, nil]
      attr_reader :context

      # @param message [String]
      # @param context [String, nil]
      # @param location [Location]
      def initialize(message, location:, context: nil)
        @line = location.line
        @column = location.column
        @context = context
        composed = context ? "#{message} (context: #{context})" : message
        super(composed, location: location)
      end

      # @param message [String]
      # @param line [Integer]
      # @param column [Integer]
      # @param offset [Integer, nil]
      # @param length [Integer, nil]
      # @param context [String, nil]
      # @return [ParserError]
      def self.from_position(message, line:, column:, offset: nil, length: nil, context: nil)
        location = Location.new(line: line, column: column, offset: offset, length: length)
        new(message, location: location, context: context)
      end
    end

    # Error raised during evaluation.
    class EvaluationError < Error
      # @return [Object, nil]
      attr_reader :rule

      # @param message [String]
      # @param rule [Object, nil]
      # @param location [Location, nil]
      def initialize(message, rule: nil, location: nil)
        @rule = rule
        details = ErrorFormatting.format_details(rule: rule)
        composed = details.empty? ? message : "#{message} (#{details})"
        super(composed, location: location)
      end
    end

    # Error raised for type-checking issues.
    class TypeError < Error
      # @return [Object, nil]
      attr_reader :expected

      # @return [Object, nil]
      attr_reader :actual

      # @return [String, nil]
      attr_reader :context

      # @param message [String]
      # @param expected [Object, nil]
      # @param actual [Object, nil]
      # @param context [String, nil]
      # @param location [Location, nil]
      def initialize(message, expected: nil, actual: nil, context: nil, location: nil)
        @expected = expected
        @actual = actual
        @context = context
        details = ErrorFormatting.format_details(expected: expected, actual: actual, context: context)
        composed = details.empty? ? message : "#{message} (#{details})"
        super(composed, location: location)
      end
    end

    # Error raised during unification/pattern matching.
    class UnificationError < Error
      # @return [Object, nil]
      attr_reader :pattern

      # @return [Object, nil]
      attr_reader :value

      # @param message [String]
      # @param pattern [Object, nil]
      # @param value [Object, nil]
      # @param location [Location, nil]
      def initialize(message, pattern: nil, value: nil, location: nil)
        @pattern = pattern
        @value = value
        details = ErrorFormatting.format_details(pattern: pattern, value: value)
        composed = details.empty? ? message : "#{message} (#{details})"
        super(composed, location: location)
      end
    end
  end
end
