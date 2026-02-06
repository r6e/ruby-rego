# frozen_string_literal: true

require_relative "../ast"
require_relative "../value"

module Ruby
  module Rego
    # Reference resolution helpers for Environment.
    module EnvironmentReferenceResolution
      # @param ref [Object]
      # @return [Value]
      # :reek:FeatureEnvy
      def resolve_reference(ref)
        base, path = if ref.is_a?(AST::Reference)
                       [ref.base, ref.path]
                     else
                       path = [] # @type var path: Array[AST::RefArg]
                       [ref, path]
                     end
        resolve_reference_path(resolve_base(base), path)
      end

      # @param variable [AST::Variable]
      # @return [Object]
      def reference_key_for(variable)
        resolve_reference_variable(variable)
      end

      private

      # :reek:TooManyStatements
      # :reek:FeatureEnvy
      def resolve_base(base)
        return lookup(base.name) if base.is_a?(AST::Variable)
        return base if base.is_a?(Value)
        return lookup(base.to_s) if base.is_a?(String) || base.is_a?(Symbol)

        value = base.is_a?(AST::Literal) ? base.value : base
        Value.from_ruby(value)
      rescue ArgumentError
        UndefinedValue.new
      end

      # :reek:FeatureEnvy
      def resolve_path_segment(current, segment)
        key = extract_reference_key(segment)
        return UndefinedValue.new if key.is_a?(UndefinedValue)

        return current.fetch(key) if current.is_a?(ObjectValue)
        return current.fetch_index(key) if current.is_a?(ArrayValue)

        UndefinedValue.new
      end

      # :reek:FeatureEnvy
      def resolve_reference_path(current, path)
        path.each do |segment|
          current = resolve_path_segment(current, segment)
          return current if current.is_a?(UndefinedValue)
        end
        current
      end

      # :reek:TooManyStatements
      # :reek:FeatureEnvy
      def extract_reference_key(segment)
        value = segment.is_a?(AST::RefArg) ? segment.value : segment
        return value.value if value.is_a?(AST::Literal)
        return resolve_reference_variable(value) if value.is_a?(AST::Variable)
        return value.to_ruby if value.is_a?(Value)

        Value.from_ruby(value).to_ruby
      rescue ArgumentError
        UndefinedValue.new
      end

      # :reek:FeatureEnvy
      def resolve_reference_variable(value)
        resolved = lookup(value.name)
        return resolved if resolved.is_a?(UndefinedValue)

        resolved.to_ruby
      end
    end
  end
end
