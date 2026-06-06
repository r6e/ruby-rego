# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Resolves AST references against input/data and rule outputs.
      class ReferenceResolver
        UNCACHEABLE = Object.new.freeze

        # @param environment [Environment]
        # @param package_path [Array<String>]
        # @param rule_value_provider [RuleValueProvider]
        # @param memoization [Memoization::Store, nil]
        def initialize(environment:, package_path:, rule_value_provider:, imports: [], memoization: nil)
          @environment = environment
          @package_path = package_path
          @rule_value_provider = rule_value_provider
          @memoization = memoization
          @key_resolver = ReferenceKeyResolver.new(
            environment: environment,
            variable_resolver: method(:resolve_variable_key)
          )
          @import_map = build_import_map(imports)
          @module_resolver = nil
        end

        # Attach the cross-package module registry.
        #
        # @param module_resolver [ModuleContextRegistry]
        # @return [void]
        def attach_module_resolver(module_resolver)
          @module_resolver = module_resolver
        end

        # @param ref [Object]
        # @return [Value]
        def resolve(ref)
          return environment.resolve_reference(ref) unless ref.is_a?(AST::Reference)

          cached = cached_reference_value(ref)
          return cached if cached

          value = resolve_reference_value(ref)
          cache_reference_value(ref, value) if cacheable_reference?(ref)
          value
        end

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

          rule_or_override_value(name)
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

        attr_reader :environment, :package_path, :rule_value_provider, :key_resolver, :import_map, :memoization,
                    :module_resolver
      end
    end
  end
end

require_relative "reference_resolver/static_key_builder"
require_relative "reference_resolver/path_resolution"
require_relative "reference_resolver/imports"
require_relative "reference_resolver/caching"
