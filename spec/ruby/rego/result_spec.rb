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

    # An invalid-UTF-8 / ASCII-8BIT (binary) string in the output value — e.g. a base64.decode result,
    # including as an object KEY — must serialize like Go's encoding/json (each invalid byte sequence ->
    # U+FFFD), matching OPA, rather than raising JSON::GeneratorError (which would escape uncaught).
    it "replaces invalid-UTF-8 / binary bytes with U+FFFD in JSON output (matching OPA), never raising" do
      binary_key = (+"\x80").force_encoding("ASCII-8BIT") # opa: "�"
      lone_surrogate = (+"\xED\xA0\x80").force_encoding("ASCII-8BIT") # opa: "���"
      result = described_class.new(
        value: { binary_key => "v", "valid-é" => lone_surrogate, "nested" => [binary_key] },
        success: true
      )

      payload = nil
      expect { payload = JSON.parse(result.to_json) }.not_to raise_error
      expect(payload["value"]).to eq(
        { "�" => "v", "valid-é" => "���", "nested" => ["�"] }
      )
    end

    it "uses Go's per-byte U+FFFD granularity (one per invalid byte), not Ruby scrub's grouping" do
      # "\xE0\xA0" is a truncated 3-byte lead+continuation: Go (and OPA) emit 2 U+FFFD (one per byte),
      # whereas Ruby's bare scrub("�") would collapse it to 1. The valid 'A' after must survive.
      result = described_class.new(value: { "k" => (+"\xE0\xA0\x41").force_encoding("ASCII-8BIT") }, success: true)
      expect(JSON.parse(result.to_json)["value"]["k"]).to eq("\u{FFFD}\u{FFFD}A")
    end

    it "serializes a Set value (not raising), matching OPA's array form" do
      result = described_class.new(value: Set.new([(+"\x80").force_encoding("ASCII-8BIT"), "ok"]), success: true)
      expect { JSON.parse(result.to_json) }.not_to raise_error
      expect(JSON.parse(result.to_json)["value"]).to contain_exactly("�", "ok")
    end

    # A number beyond Float range read from input/data JSON (e.g. {"n": 1e999}) parses to a non-finite
    # Float, which is not valid JSON. Serialization must stay total (emit null) rather than raising
    # JSON::GeneratorError. Rego literals/arithmetic can no longer produce this; only lossy input can.
    it "emits null for a non-finite Float instead of raising (totality)" do
      result = described_class.new(value: { "n" => Float::INFINITY, "m" => Float::NAN, "ok" => 1.5 }, success: true)
      payload = nil
      expect { payload = JSON.parse(result.to_json) }.not_to raise_error
      expect(payload["value"]).to eq({ "n" => nil, "m" => nil, "ok" => 1.5 })
    end

    it "leaves valid UTF-8 and ASCII output unchanged" do
      result = described_class.new(value: { "Xé" => "普通话", "a" => "b" }, success: true)
      expect(JSON.parse(result.to_json)["value"]).to eq({ "Xé" => "普通话", "a" => "b" })
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
