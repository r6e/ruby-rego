# frozen_string_literal: true

require_relative "ast"

module Ruby
  module Rego
    # Shared call name resolution helpers.
    # NOTE: Internal helper module, not a stable public API.
    module CallName
      module_function

      def call_name(node)
        return node.name if node.is_a?(AST::Variable)
        return node.to_s if node.is_a?(String) || node.is_a?(Symbol)
        return reference_call_name(node) if node.is_a?(AST::Reference)

        nil
      end

      def reference_call_name(reference)
        base_name = reference_base_name(reference)
        return nil unless base_name

        segments = reference_call_segments(reference.path)
        return nil unless segments

        ([base_name] + segments).join(".")
      end

      def reference_base_name(reference)
        base = reference.base
        base.is_a?(AST::Variable) ? base.name : nil
      end

      def reference_call_segments(path)
        segments = path.map { |segment| dot_ref_segment_value(segment) }
        return nil if segments.any?(&:nil?)

        segments.compact
      end

      def dot_ref_segment_value(segment)
        value = segment.value
        case segment
        when AST::DotRefArg
          return value.to_s if value.is_a?(String) || value.is_a?(Symbol)
        when AST::BracketRefArg
          return value.value.to_s if value.is_a?(AST::StringLiteral)
        end

        nil
      end
    end
  end
end
