# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Resolves AST references against input/data and rule outputs.
      class ReferenceResolver
        # @param environment [Environment]
        # @param package_path [Array<String>]
        # @param rule_value_provider [RuleValueProvider]
        def initialize(environment:, package_path:, rule_value_provider:)
          @environment = environment
          @package_path = package_path
          @rule_value_provider = rule_value_provider
          @key_resolver = ReferenceKeyResolver.new(environment: environment)
        end

        # @param ref [Object]
        # @return [Value]
        def resolve(ref)
          resolved = environment.resolve_reference(ref)
          return resolved unless ref.is_a?(AST::Reference)

          rule_value = resolve_rule_reference(ref)
          rule_value || resolved
        end

        private

        attr_reader :environment, :package_path, :rule_value_provider, :key_resolver

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
      end
    end
  end
end
