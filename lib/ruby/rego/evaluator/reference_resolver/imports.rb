# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Bare-variable resolution (imports and rule names) and the import lookup map.
      class ReferenceResolver
        private

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

          value = rule_or_override_value(base.name)
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
    end
  end
end
