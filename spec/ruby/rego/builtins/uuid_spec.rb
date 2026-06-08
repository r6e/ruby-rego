# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
# All expected values were verified against `opa eval` 1.17.

RSpec.describe "uuid builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  def parse(string)
    registry.call("uuid.parse", [string]).to_ruby
  end

  describe "uuid.parse" do
    it "decodes a version 1 UUID's full component set" do
      expect(parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")).to eq(
        "version" => 1, "variant" => "RFC4122", "time" => 886_630_433_151_182_400,
        "nodeid" => "00-c0-4f-d4-30-c8", "macvariables" => "global:unicast", "clocksequence" => 180
      )
    end

    it "returns only version and variant for versions 3, 4, and 5" do
      expect(parse("123e4567-e89b-42d3-a456-426614174000")).to eq("version" => 4, "variant" => "RFC4122")
      expect(parse("a3bb189e-8bf9-3888-9912-ace4e6543002")).to eq("version" => 3, "variant" => "RFC4122")
      expect(parse("886313e1-3b8a-5372-9b90-0c9aee199e5d")).to eq("version" => 5, "variant" => "RFC4122")
    end

    it "adds id and domain for a version 2 (DCE) UUID" do
      expect(parse("6ba7b810-9dad-21d1-80b4-00c04fd430c8")).to include(
        "version" => 2, "id" => 1_806_153_744, "domain" => "Domain180", "clocksequence" => 180
      )
    end

    it "reports the nil UUID as version 0, variant Reserved" do
      expect(parse("00000000-0000-0000-0000-000000000000")).to eq("version" => 0, "variant" => "Reserved")
    end

    it "decodes the variant from byte 8" do
      expect(parse("6ba7b810-9dad-41d1-c0b4-00c04fd430c8")["variant"]).to eq("Microsoft")
      expect(parse("6ba7b810-9dad-41d1-e0b4-00c04fd430c8")["variant"]).to eq("Future")
      expect(parse("6ba7b810-9dad-41d1-00b4-00c04fd430c8")["variant"]).to eq("Reserved")
    end

    it "decodes the MAC local/global and unicast/multicast bits" do
      base = "6ba7b810-9dad-11d1-80b4-0%d0000000000"
      expect(parse(format(base, 1))["macvariables"]).to eq("global:multicast")
      expect(parse(format(base, 3))["macvariables"]).to eq("local:multicast")
      expect(parse(format(base, 2))["macvariables"]).to eq("local:unicast")
    end

    it "accepts unhyphenated, urn:uuid:, and brace-wrapped forms (case-insensitive)" do
      canonical = parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
      expect(parse("6BA7B810-9DAD-11D1-80B4-00C04FD430C8")).to eq(canonical)
      expect(parse("6ba7b8109dad11d180b400c04fd430c8")).to eq(canonical)
      expect(parse("urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8")).to eq(canonical)
      expect(parse("URN:UUID:6ba7b810-9dad-11d1-80b4-00c04fd430c8")).to eq(canonical)
      expect(parse("{6ba7b810-9dad-11d1-80b4-00c04fd430c8}")).to eq(canonical)
    end

    it "reads only the inner 36 chars of a length-38 input, not validating the delimiters (like OPA)" do
      # google/uuid (and thus OPA) takes s[1..36] without checking the outer two chars, so these
      # all parse despite not being properly brace-wrapped (verified vs opa eval).
      canonical = parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
      expect(parse("{6ba7b810-9dad-11d1-80b4-00c04fd430c8X")).to eq(canonical)
      expect(parse("X6ba7b810-9dad-11d1-80b4-00c04fd430c8}")).to eq(canonical)
      expect(parse("_6ba7b810-9dad-11d1-80b4-00c04fd430c8_")).to eq(canonical)
    end

    it "wraps the time to a signed 64-bit integer like OPA's int64 arithmetic" do
      # Extreme (non-real) timestamps overflow OPA's int64 time; the gem matches the wraparound.
      expect(parse("00000000-0000-1000-8000-000000000000")["time"]).to eq(6_227_451_273_709_551_616)
      expect(parse("ffffffff-ffff-1fff-bfff-ffffffffffff")["time"]).to eq(-7_607_606_781_572_612_196)
    end

    it "dispatches on byte length, so a multibyte outer char is undefined (matching OPA)" do
      # 38 characters but 39 bytes (é is 2 bytes); OPA's len() is byte-based, so this is invalid.
      expect(registry.call("uuid.parse", ["{6ba7b810-9dad-11d1-80b4-00c04fd430c8é"]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for an unparseable UUID" do
      ["6ba7b810-9dad-11d1-80b4-00c04fd430c", "6ba7b810-9dad-11d1-80b4-00c04fd430c8x",
       "zzzzzzzz-9dad-11d1-80b4-00c04fd430c8", "6ba7b810_9dad_11d1_80b4_00c04fd430c8", ""].each do |bad|
        expect(registry.call("uuid.parse", [bad])).to be_a(Ruby::Rego::UndefinedValue)
      end
    end

    it "is undefined for a non-string argument" do
      expect(registry.call("uuid.parse", [123])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "allows repeated registration" do
      expect { Ruby::Rego::Builtins::Uuid.register! }.not_to raise_error
    end
  end
end
# rubocop:enable Metrics/BlockLength
