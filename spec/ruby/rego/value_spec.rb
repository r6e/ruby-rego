# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

RSpec.describe Ruby::Rego::Value do
  describe ".from_ruby" do
    it "wraps primitive Ruby values" do
      string_value = build(:rego_string_value)
      number_value = build(:rego_number_value)
      boolean_value = build(:rego_boolean_value)

      expect(described_class.from_ruby(string_value.to_ruby)).to be_a(Ruby::Rego::StringValue)
      expect(described_class.from_ruby(number_value.to_ruby)).to be_a(Ruby::Rego::NumberValue)
      expect(described_class.from_ruby(boolean_value.to_ruby)).to be_a(Ruby::Rego::BooleanValue)
      expect(described_class.from_ruby(nil)).to be_a(Ruby::Rego::NullValue)
    end

    it "wraps arrays, objects, and sets recursively" do
      ruby_set = Set.new(["admin", 3])
      ruby_hash = { "roles" => ruby_set, :enabled => true }
      value = described_class.from_ruby([ruby_hash, "x"])

      expect(value).to be_a(Ruby::Rego::ArrayValue)
      expect(value.to_ruby[0]).to eq({ "roles" => ruby_set, "enabled" => true })
      expect(value.to_ruby[1]).to eq("x")
    end

    it "raises when string and symbol keys collide" do
      expect do
        described_class.from_ruby({ "status" => "ok", :status => "warn" })
      end.to raise_error(Ruby::Rego::Error, /Conflicting object keys/)
    end
  end

  describe "truthiness" do
    it "treats false, null, and undefined as falsy" do
      expect(Ruby::Rego::BooleanValue.new(false).truthy?).to be(false)
      expect(Ruby::Rego::NullValue.new.truthy?).to be(false)
      expect(Ruby::Rego::UndefinedValue.new.truthy?).to be(false)
    end

    it "treats non-boolean values as truthy" do
      expect(build(:rego_string_value).truthy?).to be(true)
      expect(build(:rego_number_value).truthy?).to be(true)
      expect(Ruby::Rego::ArrayValue.new(["x"]).truthy?).to be(true)
    end
  end

  describe "equality" do
    it "compares by value and type" do
      expect(Ruby::Rego::StringValue.new("a")).to eq(Ruby::Rego::StringValue.new("a"))
      expect(Ruby::Rego::StringValue.new("a")).not_to eq(Ruby::Rego::StringValue.new("b"))
      expect(Ruby::Rego::StringValue.new("1")).not_to eq(Ruby::Rego::NumberValue.new(1))
    end
  end

  describe Ruby::Rego::UndefinedValue do
    it "returns a stable undefined sentinel" do
      expect(described_class.new.to_ruby).to eq(Ruby::Rego::UndefinedValue::UNDEFINED)
    end
  end
end

# rubocop:enable Metrics/BlockLength
