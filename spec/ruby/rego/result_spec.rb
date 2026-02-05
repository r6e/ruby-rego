# frozen_string_literal: true

RSpec.describe Ruby::Rego::Result do
  describe "result state" do
    it "exposes success and bindings" do
      result = described_class.new(
        value: "ok",
        bindings: { "user" => build(:rego_string_value).to_ruby },
        success: true,
        errors: []
      )

      expect(result.success?).to be(true)
      expect(result.value).to be_a(Ruby::Rego::StringValue)
      expect(result.bindings["user"]).to be_a(Ruby::Rego::StringValue)
    end

    it "detects undefined results" do
      result = described_class.new(
        value: Ruby::Rego::UndefinedValue.new,
        bindings: {},
        success: false,
        errors: ["missing"]
      )

      expect(result.undefined?).to be(true)
      expect(result.to_h[:value]).to eq(Ruby::Rego::UndefinedValue::UNDEFINED)
    end
  end
end
