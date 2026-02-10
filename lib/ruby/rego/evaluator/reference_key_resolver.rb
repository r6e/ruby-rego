# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Resolves reference path segments to Ruby keys.
      class ReferenceKeyResolver
        # @param environment [Environment]
        # @param variable_resolver [#call]
        def initialize(environment:, variable_resolver: nil)
          @environment = environment
          @variable_resolver = variable_resolver
        end

        # @param segment [Object]
        # @return [Object]
        def resolve(segment)
          resolve_segment(segment)
        rescue ArgumentError
          UndefinedValue.new
        end

        private

        attr_reader :environment, :variable_resolver

        def resolve_segment(segment)
          case segment
          in AST::RefArg[value: value]
            resolve_segment(value)
          in AST::Literal[value:] then value
          in AST::Variable => variable then resolve_variable_key(variable)
          in Value => value then value.to_ruby
          in value then Value.from_ruby(value).to_ruby
          end
        end

        def resolve_variable_key(variable)
          return environment.reference_key_for(variable) unless variable_resolver

          resolved = variable_resolver.call(variable.name)
          return UndefinedValue.new if resolved.is_a?(UndefinedValue)
          return resolved.to_ruby if resolved.is_a?(Value)

          Value.from_ruby(resolved).to_ruby
        end
      end
    end
  end
end
