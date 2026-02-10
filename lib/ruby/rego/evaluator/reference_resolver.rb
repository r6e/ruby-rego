# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Resolves AST references against input/data and rule outputs.
      # rubocop:disable Metrics/ClassLength
      class ReferenceResolver
        # @param environment [Environment]
        # @param package_path [Array<String>]
        # @param rule_value_provider [RuleValueProvider]
        def initialize(environment:, package_path:, rule_value_provider:, imports: [])
          @environment = environment
          @package_path = package_path
          @rule_value_provider = rule_value_provider
          @key_resolver = ReferenceKeyResolver.new(
            environment: environment,
            variable_resolver: method(:resolve_variable_key)
          )
          @import_map = build_import_map(imports)
        end

        # @param ref [Object]
        # @return [Value]
        # rubocop:disable Metrics/MethodLength
        def resolve(ref)
          if ref.is_a?(AST::Reference)
            import_value = resolve_import_reference(ref)
            return import_value if import_value

            rule_value = resolve_rule_reference_without_data(ref)
            return rule_value if rule_value
          end

          resolved = if ref.is_a?(AST::Reference)
                       base_value = environment.resolve_reference(ref.base)
                       resolve_reference_path(base_value, ref.path)
                     else
                       environment.resolve_reference(ref)
                     end
          return resolved unless ref.is_a?(AST::Reference)

          rule_value = resolve_rule_reference(ref)
          rule_value || resolved
        end
        # rubocop:enable Metrics/MethodLength

        # Resolve an import alias used as a bare variable.
        #
        # @param name [String]
        # @return [Value, nil]
        def resolve_import_variable(name)
          reference = import_map[name.to_s]
          return nil unless reference
          return nil if environment.local_bound?(name)
          return nil unless environment.lookup(name).is_a?(UndefinedValue)

          resolve(reference)
        end

        # Resolve a rule name used as a bare variable.
        #
        # @param name [String]
        # @return [Value, nil]
        def resolve_rule_variable(name)
          return nil if environment.local_bound?(name)
          return nil unless environment.lookup(name).is_a?(UndefinedValue)
          return nil unless rule_value_provider.rule_defined?(name)

          rule_value_provider.value_for(name)
        end

        # Resolve a function call reference to a rule name when possible.
        #
        # @param reference [AST::Reference]
        # @return [String, nil]
        def function_reference_name(reference)
          return nil unless reference.is_a?(AST::Reference)

          target = function_reference_target(reference)
          return nil unless target

          resolve_function_reference_name(target)
        end

        # :reek:FeatureEnvy
        def function_reference_target(reference)
          import_reference = import_reference_for(reference)
          return reference unless import_reference

          AST::Reference.new(
            base: import_reference.base,
            path: import_reference.path + reference.path,
            location: reference.location
          )
        end

        # :reek:FeatureEnvy
        def resolve_function_reference_name(reference)
          base = reference.base
          return nil unless base.is_a?(AST::Variable) && base.name == "data"

          rule_reference(reference.path)&.then do |(rule_name, remaining_path)|
            remaining_path.empty? ? rule_name : nil
          end
        end

        private

        attr_reader :environment, :package_path, :rule_value_provider, :key_resolver, :import_map

        def resolve_rule_reference(ref)
          base = ref.base
          path = ref.path
          return nil unless base.is_a?(AST::Variable) && base.name == "data"

          rule_reference(path)&.then do |(rule_name, remaining_path)|
            resolve_rule_value(rule_name, remaining_path)
          end
        end

        def rule_reference(path)
          keys = valid_reference_keys(path)
          return nil unless keys

          package_rule_reference(keys, path) || direct_rule_reference(keys, path)
        end

        def resolve_rule_value(rule_name, remaining_path)
          value = rule_value_provider.value_for(rule_name)
          return value if remaining_path.empty? || value.undefined?

          resolve_reference_path(value, remaining_path)
        end

        def package_rule_reference(keys, path)
          return nil unless package_match?(keys)

          prefix_length = package_path.length
          rule_name = keys[prefix_length].to_s
          return nil unless rule_value_provider.rule_defined?(rule_name)

          [rule_name, path[(prefix_length + 1)..] || []]
        end

        def direct_rule_reference(keys, path)
          rule_name = keys.first&.to_s
          return nil unless rule_name && rule_value_provider.rule_defined?(rule_name)

          [rule_name, path[1..] || []]
        end

        def resolve_reference_path(current, path)
          path.each do |segment|
            current = resolve_path_segment(current, segment)
            return current if current.is_a?(UndefinedValue)
          end
          current
        end

        def resolve_path_segment(current, segment)
          key = key_resolver.resolve(segment)
          return UndefinedValue.new if key.is_a?(UndefinedValue)

          current.fetch_reference(key)
        end

        def valid_reference_keys(path)
          keys = reference_keys(path)
          keys.any? { |key| key.is_a?(UndefinedValue) } ? nil : keys
        end

        def reference_keys(path)
          path.map { |segment| key_resolver.resolve(segment) }
        end

        def package_match?(keys)
          prefix_length = package_path.length
          keys.length > prefix_length && keys[0, prefix_length] == package_path
        end

        def resolve_import_reference(ref)
          import_reference = import_reference_for(ref)
          return nil unless import_reference

          combined = AST::Reference.new(
            base: import_reference.base,
            path: import_reference.path + ref.path,
            location: ref.location
          )
          resolve(combined)
        end

        # rubocop:disable Metrics/AbcSize
        def resolve_rule_reference_without_data(ref)
          base = ref.base
          return nil unless base.is_a?(AST::Variable)
          return nil if environment.local_bound?(base.name)
          return nil unless environment.lookup(base.name).is_a?(UndefinedValue)
          return nil unless rule_value_provider.rule_defined?(base.name)

          value = rule_value_provider.value_for(base.name)
          return value if ref.path.empty? || value.undefined?

          resolve_reference_path(value, ref.path)
        end
        # rubocop:enable Metrics/AbcSize

        # :reek:FeatureEnvy
        def import_reference_for(ref)
          base = ref.base
          return nil unless base.is_a?(AST::Variable)
          return nil if environment.local_bound?(base.name)
          return nil unless environment.lookup(base.name).is_a?(UndefinedValue)

          import_map[base.name]
        end

        def resolve_variable_key(name)
          resolved = environment.lookup(name)
          return resolved unless resolved.is_a?(UndefinedValue)
          return resolved if environment.local_bound?(name)

          import_value = resolve_import_variable(name)
          return import_value if import_value

          rule_value = resolve_rule_variable(name)
          rule_value || resolved
        end

        def build_import_map(imports)
          # @type var import_map: Hash[String, AST::Reference]
          import_map = {}
          Array(imports).each_with_object(import_map) do |import, acc|
            path = import_path_segments(import)
            next if path.empty?

            name = import.alias_name || path.last
            acc[name.to_s] = build_reference_from_path(path)
          end
        end

        def import_path_segments(import)
          raw = import.path
          return raw if raw.is_a?(Array)
          return [] if raw.nil?

          raw.to_s.split(".")
        end

        def build_reference_from_path(path)
          base_name, *segments = path
          AST::Reference.new(
            base: AST::Variable.new(name: base_name.to_s),
            path: segments.map { |segment| AST::DotRefArg.new(value: segment.to_s) }
          )
        end
      end
      # rubocop:enable Metrics/ClassLength
    end
  end
end
