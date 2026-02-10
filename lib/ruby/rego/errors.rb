# frozen_string_literal: true

require_relative "location"

module Ruby
  # Ruby Rego implementation namespace.
  module Rego
    # Shared formatting helpers for error message details.
    module ErrorFormatting
      # Format detail key/value pairs for error messages.
      #
      # @param details [Hash{Symbol => Object}]
      # @return [String]
      def self.format_details(details)
        details.compact.map { |key, value| "#{key}: #{value}" }.join(", ")
      end
    end

    private_constant :ErrorFormatting

    # Base error for all Ruby::Rego exceptions.
    class Error < StandardError
      # @return [Location, nil]
      attr_reader :location

      # Create a new error with optional location details.
      #
      # @param message [String, nil] error message
      # @param location [Location, nil] source location
      def initialize(message = nil, location: nil)
        @raw_message = message
        @location = location
        super(compose_message(message))
      end

      # Serialize the error to a hash.
      #
      # @return [Hash{Symbol => Object}]
      def to_h
        {
          message: raw_message,
          type: self.class.name,
          location: location&.to_s
        }
      end

      private

      attr_reader :raw_message

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

      # Create a lexer error.
      #
      # @param message [String] error message
      # @param line [Integer] line number
      # @param column [Integer] column number
      # @param offset [Integer, nil] character offset
      # @param length [Integer, nil] token length
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

      # Create a parser error.
      #
      # @param message [String] error message
      # @param context [String, nil] token context
      # @param location [Location] error location
      def initialize(message, location:, context: nil)
        @line = location.line
        @column = location.column
        @context = context
        composed = context ? "#{message} (context: #{context})" : message
        super(composed, location: location)
      end

      # Build an error from a position hash or location.
      #
      # @param message [String] error message
      # @param position [Hash, Location] source position
      # @param context [String, nil] token context
      # @return [ParserError]
      def self.from_position(message, position:, context: nil)
        location = Location.from(position)
        new(message, location: location, context: context)
      end
    end

    # Error raised during module compilation.
    class CompilationError < Error
    end

    # Error raised during evaluation.
    class EvaluationError < Error
      # @return [Object, nil]
      attr_reader :rule

      # Create an evaluation error.
      #
      # @param message [String] error message
      # @param rule [Object, nil] rule context
      # @param location [Location, nil] source location
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

      # Create a type error.
      #
      # @param message [String] error message
      # @param expected [Object, nil] expected type or value
      # @param actual [Object, nil] actual type or value
      # @param context [String, nil] error context
      # @param location [Location, nil] source location
      def initialize(message, expected: nil, actual: nil, context: nil, location: nil)
        @expected = expected
        @actual = actual
        @context = context
        details = ErrorFormatting.format_details(expected: expected, actual: actual, context: context)
        composed = details.empty? ? message : "#{message} (#{details})"
        super(composed, location: location)
      end
    end

    # Error raised for invalid builtin arguments.
    class BuiltinArgumentError < TypeError
    end

    # Error raised when object keys normalize to the same value.
    class ObjectKeyConflictError < Error
    end

    # Error raised during unification/pattern matching.
    class UnificationError < Error
      # @return [Object, nil]
      attr_reader :pattern

      # @return [Object, nil]
      attr_reader :value

      # Create a unification error.
      #
      # @param message [String] error message
      # @param pattern [Object, nil] pattern being matched
      # @param value [Object, nil] value being matched
      # @param location [Location, nil] source location
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
