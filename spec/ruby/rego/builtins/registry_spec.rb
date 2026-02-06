# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

require "securerandom"

RSpec.describe Ruby::Rego::Builtins::BuiltinRegistry do
  let(:registry) { described_class.instance }

  describe "#register" do
    it "registers and calls builtins" do
      name = "spec_registry_#{SecureRandom.hex(4)}"
      registry.register(name, 2) do |left, right|
        Ruby::Rego::NumberValue.new(left.value + right.value)
      end

      expect(registry.registered?(name)).to be(true)

      result = registry.call(
        name,
        [Ruby::Rego::NumberValue.new(1), Ruby::Rego::NumberValue.new(2)]
      )
      expect(result).to eq(Ruby::Rego::NumberValue.new(3))
    end
  end

  describe "#call" do
    it "raises for undefined builtins" do
      expect { registry.call("missing_builtin_#{SecureRandom.hex(4)}", []) }
        .to raise_error(Ruby::Rego::EvaluationError, /Undefined built-in function/)
    end

    it "raises when args are not an array" do
      name = "spec_args_#{SecureRandom.hex(4)}"
      registry.register(name, 1) { |value| value }

      expect { registry.call(name, "not-array") }
        .to raise_error(Ruby::Rego::TypeError, /Expected arguments to be an Array/)
    end

    it "raises for arity mismatch" do
      name = "spec_arity_#{SecureRandom.hex(4)}"
      registry.register(name, 1) { |value| value }

      expect { registry.call(name, []) }
        .to raise_error(Ruby::Rego::TypeError, /Wrong number of arguments/)
    end
  end
end

# rubocop:enable Metrics/BlockLength
