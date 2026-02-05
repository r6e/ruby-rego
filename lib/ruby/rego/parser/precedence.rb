# frozen_string_literal: true

require_relative "../token"

module Ruby
  module Rego
    class Parser
      # Operator precedence table for binary operators.
      # :reek:TooManyConstants
      module Precedence
        LOWEST = 0
        ASSIGNMENT = 1
        OR = 2
        AND = 3
        EQUALS = 4
        COMPARE = 5
        SUM = 6
        PRODUCT = 7
        UNARY = 8

        BINARY = {
          TokenType::ASSIGN => ASSIGNMENT,
          TokenType::UNIFY => ASSIGNMENT,
          TokenType::PIPE => OR,
          TokenType::AMPERSAND => AND,
          TokenType::EQ => EQUALS,
          TokenType::NEQ => EQUALS,
          TokenType::LT => COMPARE,
          TokenType::LTE => COMPARE,
          TokenType::GT => COMPARE,
          TokenType::GTE => COMPARE,
          TokenType::PLUS => SUM,
          TokenType::MINUS => SUM,
          TokenType::STAR => PRODUCT,
          TokenType::SLASH => PRODUCT,
          TokenType::PERCENT => PRODUCT
        }.freeze
      end
    end
  end
end
