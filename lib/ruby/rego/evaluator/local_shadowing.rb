# frozen_string_literal: true

module Ruby
  module Rego
    class Evaluator
      # Shared local-variable shadowing for comprehension and `every` bodies. Binds
      # explicitly-declared locals and unification-introduced locals to undefined before the
      # body is evaluated, so an outer binding of the same name does not leak into the scope.
      module LocalShadowing
        private

        def shadow_explicit_locals(names)
          names.each { |name| bind_undefined(name) }
        end

        def shadow_unification_locals(names, explicit_names)
          names.each do |name|
            next if explicit_names.include?(name)
            next unless environment.lookup(name).is_a?(UndefinedValue)
            # A name that resolves to a rule or import is a value, not a binding
            # target: shadowing it would hide the rule (`x = some_rule`).
            next if imported_or_rule_variable?(name)

            bind_undefined(name)
          end
        end

        def bind_undefined(name)
          return if Environment::RESERVED_NAMES.include?(name) || name == "_"

          environment.bind(name, UndefinedValue.new)
        end
      end
    end
  end
end
