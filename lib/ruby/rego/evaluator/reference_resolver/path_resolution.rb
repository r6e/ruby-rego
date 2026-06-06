# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Reference path resolution: rule/data/cross-package resolution and path traversal.
      # rubocop:disable Metrics/ClassLength
      class ReferenceResolver
        private

        def resolve_reference_value(ref)
          import_value = resolve_import_reference(ref)
          return import_value if import_value

          rule_value = resolve_rule_reference_without_data(ref)
          return rule_value if rule_value

          base_value = environment.resolve_reference(ref.base)
          resolved = resolve_reference_path_fast(base_value, ref)
          resolve_data_reference_value(ref, resolved)
        end

        def resolve_data_reference_value(ref, resolved)
          # A `with data.<pkg>.<rule> as v` override shadows the virtual document:
          # the overridden data-tree value wins over the rule's computed value.
          return resolved if environment.data_path_overridden?(valid_reference_keys(ref.path))

          rule_value = resolve_rule_reference(ref)
          return rule_value if rule_value

          cross_value = resolve_cross_package_reference(ref)
          return cross_value if cross_value

          resolved
        end

        def resolve_rule_reference(ref)
          base = ref.base
          path = ref.path
          return nil unless base.is_a?(AST::Variable) && base.name == "data"

          rule_reference(path)&.then do |(rule_name, remaining_path)|
            resolve_rule_value(rule_name, remaining_path)
          end
        end

        def resolve_cross_package_reference(ref)
          resolver = module_resolver
          return nil unless resolver

          base = ref.base
          return nil unless base.is_a?(AST::Variable) && base.name == "data"

          keys = valid_reference_keys(ref.path)
          return nil unless keys

          owner = resolver.resolver_for(keys)
          return nil if owner.nil? || owner.equal?(self)

          owner.resolve(ref)
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

        def resolve_reference_path_fast(current, reference)
          keys = static_reference_keys(reference)
          return resolve_reference_path(current, reference.path) unless keys

          resolve_reference_path_keys(current, keys)
        end

        def resolve_reference_path_keys(current, keys)
          keys.each do |key|
            current = current.fetch_reference(key)
            return current if current.is_a?(UndefinedValue)
          end
          current
        end

        # The value of rule `name` in this package, honouring a
        # `with data.<pkg>.<name> as v` override that shadows the rule.
        def rule_or_override_value(name)
          overridden_rule_value(name) || rule_value_provider.value_for(name)
        end

        # When `with data.<pkg>.<name> as v` shadows this package's rule `name`,
        # return the override value (read from the overridden data tree) so a
        # bare `name` reference honours the override just like `data.<pkg>.name`.
        def overridden_rule_value(name)
          keys = package_path + [name.to_s]
          return nil unless environment.data_path_overridden?(keys)

          value = resolve_reference_path_keys(environment.data, keys)
          value.is_a?(UndefinedValue) ? nil : value
        end

        def resolve_path_segment(current, segment)
          key = key_resolver.resolve(segment)
          return UndefinedValue.new if key.is_a?(UndefinedValue)

          current.fetch_reference(key)
        end

        def valid_reference_keys(path)
          keys = reference_keys(path)
          keys.any?(UndefinedValue) ? nil : keys
        end

        def reference_keys(path)
          path.map { |segment| key_resolver.resolve(segment) }
        end

        def package_match?(keys)
          prefix_length = package_path.length
          keys.length > prefix_length && keys[0, prefix_length] == package_path
        end
      end
      # rubocop:enable Metrics/ClassLength
    end
  end
end
