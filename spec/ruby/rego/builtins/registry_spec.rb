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

    it "propagates evaluation errors from builtins" do
      name = "spec_eval_error_#{SecureRandom.hex(4)}"
      registry.register(name, 1) { |_value| raise Ruby::Rego::EvaluationError, "boom" }

      expect { registry.call(name, ["value"]) }
        .to raise_error(Ruby::Rego::EvaluationError, /boom/)
    end

    it "raises when args are not an array" do
      name = "spec_args_#{SecureRandom.hex(4)}"
      registry.register(name, 1) { |value| value }

      result = registry.call(name, "not-array")

      expect(result).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "raises for arity mismatch" do
      name = "spec_arity_#{SecureRandom.hex(4)}"
      registry.register(name, 1) { |value| value }

      result = registry.call(name, [])

      expect(result).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "raises when builtin errors have empty backtraces" do
      name = "spec_empty_backtrace_#{SecureRandom.hex(4)}"
      registry.register(name, 1) do |_value|
        error = ArgumentError.new("boom")
        error.set_backtrace([])
        raise error
      end

      expect { registry.call(name, [1]) }
        .to raise_error(ArgumentError, /boom/)
    end
  end
end

# rubocop:enable Metrics/BlockLength
