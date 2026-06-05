# frozen_string_literal: true

module Ruby
  module Rego
    # :reek:DataClump
    # Reference-pattern unification: base resolution, path traversal, and key-candidate enumeration.
    class Unifier
      private

      # :reek:LongParameterList
      def unify_reference(pattern, resolved_value, env, bindings)
        # @type var results: Array[Hash[String, Value]]
        results = []
        reference_bindings(pattern, env, bindings).each_with_object(results) do |(candidate_bindings, value), acc|
          next if value.is_a?(UndefinedValue)
          next unless value == resolved_value

          acc << candidate_bindings
        end
      end

      def resolve_reference_base(base, env, bindings)
        return env.input if base.is_a?(AST::Variable) && base.name == "input"
        return env.data if base.is_a?(AST::Variable) && base.name == "data"

        if base.is_a?(AST::Variable)
          bound = Helpers.bound_value_for(base.name, bindings, env)
          return bound if bound
        end

        Helpers.scalar_pattern_value(base, env)
      end

      # :reek:LongParameterList
      # rubocop:disable Metrics/CyclomaticComplexity, Metrics/MethodLength
      def traverse_reference(current, path, env, bindings, variable_resolver: nil)
        return [[bindings, current]] if path.empty?
        return [] unless current.is_a?(ObjectValue) || current.is_a?(ArrayValue)

        segment = path.first
        key_node = segment.is_a?(AST::RefArg) ? segment.value : segment
        candidates = reference_key_candidates(current, key_node, env, bindings, variable_resolver: variable_resolver)
        candidates.flat_map do |candidate_key, candidate_bindings|
          next [] if candidate_bindings.nil?

          next_value = current.fetch_reference(candidate_key)
          next [] if next_value.is_a?(UndefinedValue)

          traverse_reference(next_value, path.drop(1), env, candidate_bindings, variable_resolver: variable_resolver)
        end
      end
      # rubocop:enable Metrics/CyclomaticComplexity, Metrics/MethodLength

      # :reek:LongParameterList
      def reference_key_candidates(current, key_node, env, bindings, variable_resolver: nil)
        keys = reference_keys_for(current)
        return [] if keys.empty?

        context = ReferenceKeyContext.new(
          current: current,
          env: env,
          bindings: bindings,
          variable_resolver: variable_resolver
        )
        return variable_key_candidates(key_node, keys, context) if key_node.is_a?(AST::Variable)

        value_key_candidates(key_node, context)
      end
    end
  end
end
