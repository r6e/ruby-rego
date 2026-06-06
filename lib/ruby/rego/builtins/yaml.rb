# frozen_string_literal: true

# rubocop:disable Naming/PredicatePrefix

require "psych"
require_relative "base"
require_relative "registry"
require_relative "registry_helpers"
require_relative "yaml/scalar_resolver"
require_relative "yaml/emitter"

module Ruby
  module Rego
    module Builtins
      # Built-in YAML helpers (yaml.marshal, yaml.unmarshal, yaml.is_valid).
      #
      # OPA implements these via sigs.k8s.io/yaml, which round-trips through JSON on
      # top of gopkg.in/yaml.v2. To match byte-for-byte:
      #   - marshal delegates layout/folding/escaping to Psych (libyaml — the same
      #     engine yaml.v2 ports), and supplies the divergent pieces itself: sorted
      #     keys, Go float formatting, explicit scalar styles, and `null` for nil.
      #   - unmarshal/is_valid resolve plain scalars with a yaml.v2-compatible resolver
      #     (no timestamp resolution — timestamps stay strings, as OPA's JSON round-trip
      #     leaves them), stringify object keys (JSON keys are strings), and treat a
      #     non-finite number (Inf/NaN, unrepresentable in JSON) as undefined.
      module Yaml
        extend RegistryHelpers

        YAML_FUNCTIONS = {
          "yaml.marshal" => { arity: 1, handler: :marshal },
          "yaml.unmarshal" => { arity: 1, handler: :unmarshal },
          "yaml.is_valid" => { arity: 1, handler: :is_valid }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, YAML_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.marshal(value)
          StringValue.new(Emitter.emit(value.to_ruby))
        rescue Emitter::MarshalError, SystemStackError => e
          # SystemStackError guards value.to_ruby / node-build recursion on pathologically
          # deep input, so marshal stays total (undefined) instead of crashing.
          message = e.message
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Cannot marshal value to YAML: #{message}",
            expected: "a YAML-marshalable value",
            actual: message,
            context: "yaml.marshal",
            location: nil
          )
        end

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::Value]
        def self.unmarshal(value)
          string = string_arg(value, "yaml.unmarshal")
          decoded("yaml.unmarshal") { Value.from_ruby(ScalarResolver.load(string)) }
        end

        # A total predicate: a non-string runtime value (or any parse/resolve failure)
        # yields false rather than undefined, matching OPA's *_is_valid builtins.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.is_valid(value)
          return BooleanValue.new(false) unless value.is_a?(StringValue)

          ScalarResolver.load(value.value)
          BooleanValue.new(true)
        rescue Psych::Exception, ScalarResolver::ResolveError, ArgumentError, SystemStackError
          BooleanValue.new(false)
        end

        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [String]
        def self.string_arg(value, context)
          Base.assert_type(value, expected: StringValue, context: context)
          value.value
        end
        private_class_method :string_arg

        # Turns a Psych or resolver failure into an undefined result.
        #
        # @param context [String]
        # @return [Ruby::Rego::Value]
        def self.decoded(context)
          yield
        rescue Psych::Exception, ScalarResolver::ResolveError, ArgumentError, SystemStackError => e
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Invalid #{context} input: #{e.message}",
            expected: "valid #{context} input",
            actual: "invalid",
            context: context,
            location: nil
          )
        end
        private_class_method :decoded
      end
    end
  end
end

Ruby::Rego::Builtins::Yaml.register!
# rubocop:enable Naming/PredicatePrefix
