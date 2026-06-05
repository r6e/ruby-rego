# frozen_string_literal: true

require_relative "../ast"

module Ruby
  # Rego compilation helpers.
  module Rego
    # Normalizes a rule head into reusable accessors.
    class RuleHead
      # Create a wrapper for a rule head hash.
      #
      # @param head [Hash, nil] rule head data
      def initialize(head)
        head_hash = head.is_a?(Hash) ? head : {} # @type var head_hash: Hash[Symbol, untyped]
        @head = head_hash
      end

      # Return the rule head type.
      #
      # @return [Symbol, nil]
      def type
        head[:type]
      end

      # Return AST nodes that appear in the rule head.
      #
      # @return [Array<AST::Base>]
      def nodes
        return value_nodes if type == :complete
        return [head[:term]].compact if type == :partial_set
        return [head[:key], head[:value]].compact if type == :partial_object
        return function_nodes if type == :function

        []
      end

      # Return function argument names for a function rule head.
      #
      # @return [Array<String>]
      def function_arg_names
        return [] unless type == :function

        function_arg_nodes.filter_map { |arg| arg.is_a?(AST::Variable) ? arg.name : nil }
      end

      private

      attr_reader :head

      def value_nodes
        value = head[:value]
        value ? [value] : []
      end

      def function_nodes
        args = Array(head[:args]).compact
        value = head[:value]
        value ? args + [value] : args
      end

      def function_arg_nodes
        args = head[:args]
        args.is_a?(Array) ? args : []
      end
    end
    private_constant :RuleHead
  end
end
