# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Shared helpers for registering builtin functions.
      module RegistryHelpers
        def register_configured_functions(registry, mapping)
          mapping.each do |name, config|
            register_configured_function(registry, name, config)
          end
        end

        private

        # :reek:FeatureEnvy
        def register_configured_function(registry, name, config)
          return if registry.registered?(name)

          registry.register(name, config.fetch(:arity)) do |*args|
            public_send(config.fetch(:handler), *args)
          end
        end
      end
    end
  end
end
