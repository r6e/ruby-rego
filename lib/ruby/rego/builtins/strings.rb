# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "strings/helpers"
require_relative "strings/number_helpers"
require_relative "strings/trim_helpers"
require_relative "strings/concat"
require_relative "strings/search"
require_relative "strings/case_ops"
require_relative "strings/formatting"
require_relative "strings/split"
require_relative "strings/substring"
require_relative "strings/trim"

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        STRING_FUNCTIONS = {
          "concat" => { arity: 2, handler: :concat },
          "contains" => { arity: 2, handler: :contains },
          "startswith" => { arity: 2, handler: :startswith },
          "endswith" => { arity: 2, handler: :endswith },
          "format_int" => { arity: 2, handler: :format_int },
          "indexof" => { arity: 2, handler: :indexof },
          "lower" => { arity: 1, handler: :lower },
          "upper" => { arity: 1, handler: :upper },
          "split" => { arity: 2, handler: :split },
          "sprintf" => { arity: 2, handler: :sprintf },
          "substring" => { arity: 3, handler: :substring },
          "trim" => { arity: 2, handler: :trim },
          "trim_left" => { arity: 2, handler: :trim_left },
          "trim_right" => { arity: 2, handler: :trim_right },
          "trim_space" => { arity: 1, handler: :trim_space }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance

          STRING_FUNCTIONS.each do |name, config|
            register_function(registry, name, config)
          end

          registry
        end

        def self.register_function(registry, name, config)
          return if registry.registered?(name)

          registry.register(name, config.fetch(:arity)) do |*args|
            public_send(config.fetch(:handler), *args)
          end
        end
        private_class_method :register_function
      end
    end
  end
end

Ruby::Rego::Builtins::Strings.register!
