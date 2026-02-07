# frozen_string_literal: true

module Ruby
  module Rego
    # Represents a source location in a Rego policy.
    #
    # @example
    #   location = Ruby::Rego::Location.new(line: 3, column: 12, offset: 42, length: 5)
    #   location.to_s # => "line 3, column 12, offset 42, length 5"
    #
    class Location
      # Coerce a hash or location into a Location instance.
      #
      # @param position [Location, Hash] position data
      # @return [Location]
      def self.from(position)
        return position if position.is_a?(Location)

        new(
          line: position.fetch(:line),
          column: position.fetch(:column),
          offset: position[:offset],
          length: position[:length]
        )
      end

      # Create a new source location.
      #
      # @param line [Integer] 1-based line number
      # @param column [Integer] 1-based column number
      # @param offset [Integer, nil] 0-based character offset
      # @param length [Integer, nil] length of the token or span
      def initialize(line:, column:, offset: nil, length: nil)
        @line = line
        @column = column
        @offset = offset
        @length = length
      end

      # Line number.
      #
      # @return [Integer]
      attr_reader :line

      # Column number.
      #
      # @return [Integer]
      attr_reader :column

      # Character offset.
      #
      # @return [Integer, nil]
      attr_reader :offset

      # Length of the token or span.
      #
      # @return [Integer, nil]
      attr_reader :length

      # Convert the location to a readable string.
      #
      # @return [String]
      def to_s
        {
          line: line,
          column: column,
          offset: offset,
          length: length
        }.compact.map { |key, value| "#{key} #{value}" }.join(", ")
      end
    end
  end
end
