# frozen_string_literal: true

module Ruby
  module Rego
    # :reek:DataClump
    # Candidate-key enumeration for reference-pattern unification.
    class Unifier
      private

      def variable_key_candidates(key_node, keys, context)
        name = key_node.name
        return wildcard_key_candidates(keys, context.bindings) if name == "_"

        bound_candidate = bound_key_candidate(name, context)
        return bound_candidate if bound_candidate

        resolved_candidate = resolved_key_candidate(name, context)
        return resolved_candidate if resolved_candidate

        binding_key_candidates(name, keys, context.bindings)
      end

      def wildcard_key_candidates(keys, bindings)
        keys.map { |key| [key, bindings] }
      end

      def bound_key_candidate(name, context)
        bound = Helpers.bound_value_for(name, context.bindings, context.env)
        return nil unless bound

        [[normalize_reference_key(context.current, bound.to_ruby), context.bindings]]
      end

      def resolved_key_candidate(name, context)
        resolved = resolve_variable_reference(name, context.variable_resolver)
        return nil unless resolved

        normalized = normalize_reference_key(context.current, resolved_reference_value(resolved))
        [[normalized, context.bindings]]
      end

      def binding_key_candidates(name, keys, bindings)
        keys.map do |key|
          new_bindings = Helpers.merge_bindings(bindings, name => Value.from_ruby(key))
          [key, new_bindings]
        end
      end

      def value_key_candidates(key_node, context)
        key_value = Helpers.value_for_pattern(key_node, context.env)
        return [] if key_value.is_a?(UndefinedValue)

        [[normalize_reference_key(context.current, key_value.to_ruby), context.bindings]]
      end

      def resolved_reference_value(resolved)
        resolved.is_a?(Value) ? resolved.to_ruby : resolved
      end

      def resolve_variable_reference(name, resolver)
        return nil unless resolver

        resolved = resolver.call(name)
        return nil if resolved.nil? || resolved.is_a?(UndefinedValue)

        resolved
      end

      def reference_keys_for(current)
        case current
        when ObjectValue
          current.value.keys
        when ArrayValue
          (0...current.value.length).to_a
        else
          []
        end
      end

      def normalize_reference_key(current, key)
        return Helpers.normalize_key(key) if current.is_a?(ObjectValue)

        key
      end
    end
  end
end
