# frozen_string_literal: true

module Ruby
  module Rego
    # State-free unification helpers.
    class Unifier
      # Internal helpers that do not rely on instance state.
      module Helpers
        def self.scalar_pattern_value(pattern, env)
          return Value.from_ruby(pattern.value) if pattern.is_a?(AST::Literal)
          return env.resolve_reference(pattern) if pattern.is_a?(AST::Reference)
          return pattern if pattern.is_a?(Value)

          Value.from_ruby(pattern)
        rescue ArgumentError, ObjectKeyConflictError
          UndefinedValue.new
        end

        def self.normalize_value(value, env)
          return value if value.is_a?(Value)
          return env.resolve_reference(value) if value.is_a?(AST::Reference)
          return Value.from_ruby(value.value) if value.is_a?(AST::Literal)

          Value.from_ruby(value)
        rescue ArgumentError, ObjectKeyConflictError
          UndefinedValue.new
        end

        def self.value_for_pattern(pattern, env)
          Helpers.scalar_pattern_value(pattern, env)
        end

        def self.normalize_array(value)
          return normalize_elements(value.to_ruby) if value.is_a?(ArrayValue)
          return normalize_elements(value) if value.is_a?(Array)

          nil
        end

        def self.normalize_elements(elements)
          values = [] # @type var values: Array[Value]
          elements.each do |element|
            values << Value.from_ruby(element)
          rescue ArgumentError, ObjectKeyConflictError
            return nil
          end
          values
        end

        def self.normalize_key(key)
          key.is_a?(Symbol) ? key.to_s : key
        end

        def self.object_pairs(value)
          return value.to_ruby if value.is_a?(ObjectValue)
          return value if value.is_a?(Hash)

          nil
        end

        # :reek:TooManyStatements
        def self.normalize_object(value)
          return nil unless (pairs = object_pairs(value))

          values = {} # @type var values: Hash[Object, Value]
          pairs.each do |key, val|
            normalized_key = normalize_key(key)
            return nil if values.key?(normalized_key)

            values[normalized_key] = Value.from_ruby(val)
          end
          values
        rescue ArgumentError, ObjectKeyConflictError
          nil
        end

        def self.bound_value_for(name, bindings, env)
          bound = bindings[name]
          return bound if bound && !bound.is_a?(UndefinedValue)

          env_value = env.lookup(name)
          return nil if env_value.is_a?(UndefinedValue)

          env_value
        end

        def self.merge_bindings(bindings, additions)
          conflict = additions.any? do |name, value|
            existing = bindings[name]
            existing && existing != value
          end
          return nil if conflict

          bindings.merge(additions)
        end

        # :reek:LongParameterList
        # :reek:TooManyStatements
        def self.unify_variable(variable, value, env, bindings)
          name = variable.name
          return [bindings] if name == "_"

          bound_value = bound_value_for(name, bindings, env)
          return bound_value == value ? [bindings] : [] if bound_value

          [bindings.merge(name => value)]
        end

        # :reek:TooManyStatements
        # :reek:LongParameterList
        def self.candidate_keys_for(key_pattern, keys, env, bindings)
          if key_pattern.is_a?(AST::Variable)
            name = key_pattern.name
            return keys if name == "_"

            bound_value = bound_value_for(name, bindings, env)
            return [normalize_key(bound_value.to_ruby)] if bound_value

            return keys
          end

          key_value = value_for_pattern(key_pattern, env)
          return [] if key_value.is_a?(UndefinedValue)

          [normalize_key(key_value.to_ruby)]
        end

        # :reek:LongParameterList
        # :reek:ControlParameter
        def self.match_scalar(pattern, resolved_value, env, bindings)
          pattern_value = scalar_pattern_value(pattern, env)
          pattern_value == resolved_value ? [bindings] : []
        end

        # :reek:LongParameterList
        # :reek:TooManyStatements
        def self.bind_key_variable(key_pattern, candidate_key, bindings, env)
          return bindings unless key_pattern.is_a?(AST::Variable)

          name = key_pattern.name
          return bindings if name == "_"

          bound_value = bound_value_for(name, bindings, env)
          return bindings if bound_value

          merge_bindings(bindings, name => Value.from_ruby(candidate_key))
        end
      end
    end
  end
end
