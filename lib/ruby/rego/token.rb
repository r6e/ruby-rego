# frozen_string_literal: true

require_relative "location"

module Ruby
  module Rego
    # Token type constants used by the lexer.
    # rubocop:disable Metrics/ModuleLength
    # :reek:TooManyConstants
    module TokenType
      PACKAGE = :PACKAGE
      IMPORT = :IMPORT
      AS = :AS
      DEFAULT = :DEFAULT
      IF = :IF
      CONTAINS = :CONTAINS
      SOME = :SOME
      IN = :IN
      EVERY = :EVERY
      NOT = :NOT
      WITH = :WITH
      ELSE = :ELSE
      TRUE = :TRUE
      FALSE = :FALSE
      NULL = :NULL
      DATA = :DATA
      INPUT = :INPUT

      ASSIGN = :ASSIGN
      EQ = :EQ
      NEQ = :NEQ
      LT = :LT
      LTE = :LTE
      GT = :GT
      GTE = :GTE
      PLUS = :PLUS
      MINUS = :MINUS
      STAR = :STAR
      SLASH = :SLASH
      PERCENT = :PERCENT
      PIPE = :PIPE
      AMPERSAND = :AMPERSAND
      UNIFY = :UNIFY

      LPAREN = :LPAREN
      RPAREN = :RPAREN
      LBRACKET = :LBRACKET
      RBRACKET = :RBRACKET
      LBRACE = :LBRACE
      RBRACE = :RBRACE
      DOT = :DOT
      COMMA = :COMMA
      SEMICOLON = :SEMICOLON
      COLON = :COLON
      UNDERSCORE = :UNDERSCORE

      STRING = :STRING
      NUMBER = :NUMBER
      RAW_STRING = :RAW_STRING
      IDENT = :IDENT

      EOF = :EOF
      NEWLINE = :NEWLINE
      COMMENT = :COMMENT

      # rubocop:disable Lint/DeprecatedConstants
      KEYWORDS = [
        PACKAGE,
        IMPORT,
        AS,
        DEFAULT,
        IF,
        CONTAINS,
        SOME,
        IN,
        EVERY,
        NOT,
        WITH,
        ELSE,
        TRUE,
        FALSE,
        NULL,
        DATA,
        INPUT
      ].freeze
      # rubocop:enable Lint/DeprecatedConstants

      OPERATORS = [
        ASSIGN,
        EQ,
        NEQ,
        LT,
        LTE,
        GT,
        GTE,
        PLUS,
        MINUS,
        STAR,
        SLASH,
        PERCENT,
        PIPE,
        AMPERSAND,
        UNIFY
      ].freeze

      DELIMITERS = [
        LPAREN,
        RPAREN,
        LBRACKET,
        RBRACKET,
        LBRACE,
        RBRACE,
        DOT,
        COMMA,
        SEMICOLON,
        COLON,
        UNDERSCORE
      ].freeze

      LITERALS = [
        STRING,
        NUMBER,
        RAW_STRING,
        IDENT
      ].freeze

      SPECIALS = [
        EOF,
        NEWLINE,
        COMMENT
      ].freeze

      # @param type [Symbol]
      # @return [Boolean]
      def self.keyword?(type)
        KEYWORDS.include?(type)
      end

      # @param type [Symbol]
      # @return [Boolean]
      def self.operator?(type)
        OPERATORS.include?(type)
      end

      # @param type [Symbol]
      # @return [Boolean]
      def self.literal?(type)
        LITERALS.include?(type)
      end
    end
    # rubocop:enable Metrics/ModuleLength

    # Represents a single token emitted by the lexer.
    class Token
      # @param type [Symbol]
      # @param value [Object, nil]
      # @param location [Location, nil]
      def initialize(type:, value: nil, location: nil)
        @type = type
        @value = value
        @location = location
      end

      # @return [Symbol]
      attr_reader :type

      # @return [Object, nil]
      attr_reader :value

      # @return [Location, nil]
      attr_reader :location

      # @return [Boolean]
      def keyword?
        TokenType.keyword?(type)
      end

      # @return [Boolean]
      def operator?
        TokenType.operator?(type)
      end

      # @return [Boolean]
      def literal?
        TokenType.literal?(type)
      end

      # @return [String]
      def to_s
        parts = ["type=#{type}", "value=#{value.inspect}"]
        parts << "location=#{location}" if location
        "Token(#{parts.join(", ")})"
      end
    end
  end
end
