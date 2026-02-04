# frozen_string_literal: true

require_relative "base"

module Ruby
  module Rego
    module AST
      # Represents a rule definition.
      class Rule < Base
        RULE_TYPE_LOOKUP = %i[rule_type type kind].freeze

        # Bundles rule components for storage.
        Definition = Struct.new(:head, :body, :default_value, :else_clause, keyword_init: true)

        # @param name [String]
        # @param head [Object, nil]
        # @param body [Object, nil]
        # @param default_value [Object, nil]
        # @param else_clause [Object, nil]
        # @param location [Location, nil]
        # :reek:LongParameterList
        def initialize(name:, head: nil, body: nil, default_value: nil, else_clause: nil, location: nil)
          super(location: location)
          @name = name
          @definition = Definition.new(
            head: head,
            body: body,
            default_value: default_value,
            else_clause: else_clause
          )
        end

        # @return [String]
        attr_reader :name

        # @return [Object, nil]
        def head
          definition.head
        end

        # @return [Object, nil]
        def body
          definition.body
        end

        # @return [Object, nil]
        def default_value
          definition.default_value
        end

        # @return [Object, nil]
        def else_clause
          definition.else_clause
        end

        # @return [Boolean]
        def complete?
          rule_type == :complete
        end

        # @return [Boolean]
        def partial_set?
          rule_type == :partial_set
        end

        # @return [Boolean]
        def partial_object?
          rule_type == :partial_object
        end

        # @return [Boolean]
        def function?
          rule_type == :function
        end

        private

        # @return [Symbol, nil]
        def rule_type
          return nil unless head

          type = resolve_rule_type

          type.is_a?(String) ? type.to_sym : type
        end

        def resolve_rule_type
          type_from_object || type_from_hash
        end

        # :reek:ManualDispatch
        def type_from_object
          RULE_TYPE_LOOKUP.each do |method|
            return head.public_send(method) if head.respond_to?(method)
          end

          nil
        end

        def type_from_hash
          return nil unless head.is_a?(Hash)

          RULE_TYPE_LOOKUP.each do |key|
            return head[key] if head.key?(key)
          end

          nil
        end

        attr_reader :definition
      end
    end
  end
end
