# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Builds query nodes from user input.
      class QueryNodeBuilder
        # @param query [Object]
        def initialize(query)
          @query = query
        end

        # @return [Object]
        def build
          return query if query.is_a?(AST::Base)
          return reference_from_string if query.is_a?(String)

          Value.from_ruby(query)
        end

        private

        attr_reader :query

        def reference_from_string
          base, *path_segments = query.split(".")
          raise EvaluationError.new("Invalid query path: #{query.inspect}", rule: nil, location: nil) if
            base.to_s.empty? || path_segments.any?(&:empty?)

          AST::Reference.new(
            base: AST::Variable.new(name: base),
            path: path_segments.map { |segment| AST::DotRefArg.new(value: segment) }
          )
        end
      end
    end
  end
end
