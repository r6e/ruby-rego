# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Resolves reference path segments to Ruby keys.
      class ReferenceKeyResolver
        # @param environment [Environment]
        def initialize(environment:)
          @environment = environment
        end

        # @param segment [Object]
        # @return [Object]
        def resolve(segment)
          resolve_segment(segment)
        rescue ArgumentError
          UndefinedValue.new
        end

        private

        attr_reader :environment

        def resolve_segment(segment)
          case segment
          in AST::RefArg[value: value]
            resolve_segment(value)
          in AST::Literal[value:] then value
          in AST::Variable => variable then environment.reference_key_for(variable)
          in Value => value then value.to_ruby
          in value then Value.from_ruby(value).to_ruby
          end
        end
      end
    end
  end
end
