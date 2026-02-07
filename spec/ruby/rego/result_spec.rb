# frozen_string_literal: true

require "json"

# rubocop:disable Metrics/BlockLength

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

    it "serializes to JSON" do
      result = described_class.new(
        value: "ok",
        bindings: { "user" => "admin" },
        success: true,
        errors: ["none"]
      )

      payload = JSON.parse(result.to_json)

      expect(payload["value"]).to eq("ok")
      expect(payload["bindings"]).to eq({ "user" => "admin" })
      expect(payload["success"]).to be(true)
      expect(payload["errors"]).to eq(["none"])
    end

    it "serializes structured errors without duplicating location" do
      location = Ruby::Rego::Location.new(line: 1, column: 2)
      error = Ruby::Rego::Error.new("boom", location: location)
      result = described_class.new(
        value: "ok",
        bindings: {},
        success: false,
        errors: [error]
      )

      payload = result.to_h[:errors].first

      expect(payload[:message]).to eq("boom")
      expect(payload[:type]).to eq("Ruby::Rego::Error")
      expect(payload[:location]).to eq("line 1, column 2")
    end

    it "includes locations for non-rego errors when available" do
      location = Ruby::Rego::Location.new(line: 3, column: 4)
      error_class = Class.new(StandardError) do
        attr_reader :location

        def initialize(location)
          @location = location
          super("kaboom")
        end
      end

      result = described_class.new(
        value: "ok",
        bindings: {},
        success: false,
        errors: [error_class.new(location)]
      )

      payload = result.to_h[:errors].first

      expect(payload[:message]).to eq("kaboom")
      expect(payload[:location]).to eq("line 3, column 4")
    end
  end
end

# rubocop:enable Metrics/BlockLength
