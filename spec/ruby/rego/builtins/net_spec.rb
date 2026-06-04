# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
# All expected values below were verified against `opa eval` 1.17.
RSpec.describe "net builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  describe "net.cidr_contains" do
    it "is true when the cidr contains an IP" do
      expect(registry.call("net.cidr_contains", ["10.0.0.0/8", "10.1.2.3"]).to_ruby).to be(true)
      expect(registry.call("net.cidr_contains", ["10.0.0.0/8", "11.1.2.3"]).to_ruby).to be(false)
    end

    it "is true when the cidr contains a sub-cidr but not a super-cidr" do
      expect(registry.call("net.cidr_contains", ["10.0.0.0/8", "10.1.0.0/16"]).to_ruby).to be(true)
      expect(registry.call("net.cidr_contains", ["10.0.0.0/16", "10.0.0.0/8"]).to_ruby).to be(false)
    end

    it "handles IPv6 and masks host bits in the cidr" do
      expect(registry.call("net.cidr_contains", ["2001:db8::/32", "2001:db8:1::1"]).to_ruby).to be(true)
      expect(registry.call("net.cidr_contains", ["10.0.0.5/8", "10.1.2.3"]).to_ruby).to be(true)
    end

    it "is false across address families" do
      expect(registry.call("net.cidr_contains", ["10.0.0.0/8", "2001:db8::1"]).to_ruby).to be(false)
    end

    it "treats an IPv4-mapped IPv6 cidr/address as its native IPv4 (matching OPA)" do
      expect(registry.call("net.cidr_contains", ["::ffff:10.0.0.0/120", "10.0.0.5"]).to_ruby).to be(true)
      expect(registry.call("net.cidr_contains", ["10.0.0.0/24", "::ffff:10.0.0.5"]).to_ruby).to be(true)
      # below /96 the ::ffff: prefix is not fully covered, so it stays IPv6 (OPA agrees)
      expect(registry.call("net.cidr_contains", ["::ffff:10.0.0.0/95", "10.0.0.5"]).to_ruby).to be(false)
    end

    it "is undefined for a dotted-decimal netmask (OPA requires an integer prefix)" do
      expect(registry.call("net.cidr_contains", ["10.0.0.0/255.0.0.0", "10.1.2.3"]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined when the first argument is not a cidr (bare IP or garbage)" do
      expect(registry.call("net.cidr_contains", ["10.0.0.1", "10.0.0.1"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_contains", ["not-cidr", "10.0.0.1"])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a non-string argument" do
      expect(registry.call("net.cidr_contains", [10, "10.0.0.1"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_contains", ["10.0.0.0/8", ["x"]])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "net.cidr_intersects" do
    it "is true when one cidr contains the other" do
      expect(registry.call("net.cidr_intersects", ["10.0.0.0/8", "10.1.0.0/16"]).to_ruby).to be(true)
      expect(registry.call("net.cidr_intersects", ["10.0.0.0/8", "10.0.0.0/8"]).to_ruby).to be(true)
    end

    it "is false for disjoint cidrs" do
      expect(registry.call("net.cidr_intersects", ["10.0.0.0/16", "10.1.0.0/16"]).to_ruby).to be(false)
    end

    it "handles IPv6 and is false across families" do
      expect(registry.call("net.cidr_intersects", ["2001:db8::/32", "2001:db8:abcd::/48"]).to_ruby).to be(true)
      expect(registry.call("net.cidr_intersects", ["10.0.0.0/8", "2001:db8::/32"]).to_ruby).to be(false)
    end

    it "normalizes an IPv4-mapped IPv6 cidr to native IPv4 (matching OPA)" do
      expect(registry.call("net.cidr_intersects", ["::ffff:10.0.0.0/120", "10.0.0.0/24"]).to_ruby).to be(true)
    end

    it "is undefined when either argument is not a cidr (bare IP or garbage)" do
      expect(registry.call("net.cidr_intersects", ["10.0.0.0/8", "10.1.2.3"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_intersects", ["10.0.0.1", "10.0.0.1"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_intersects", ["10.0.0.0/8", "garbage"])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a non-string argument" do
      expect(registry.call("net.cidr_intersects", [1, "10.0.0.0/8"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "net.cidr_is_valid" do
    it "is true for valid CIDR notation (v4 and v6)" do
      expect(registry.call("net.cidr_is_valid", ["192.168.0.0/24"]).to_ruby).to be(true)
      expect(registry.call("net.cidr_is_valid", ["2001:db8::/32"]).to_ruby).to be(true)
    end

    it "accepts a cidr with host bits set" do
      expect(registry.call("net.cidr_is_valid", ["192.168.0.5/24"]).to_ruby).to be(true)
    end

    it "is false for a bare IP (no prefix), bad mask, abbreviated, or garbage" do
      expect(registry.call("net.cidr_is_valid", ["192.168.0.1"]).to_ruby).to be(false)
      expect(registry.call("net.cidr_is_valid", ["10.0.0.0/33"]).to_ruby).to be(false)
      expect(registry.call("net.cidr_is_valid", ["10/8"]).to_ruby).to be(false)
      expect(registry.call("net.cidr_is_valid", ["not-a-cidr"]).to_ruby).to be(false)
      expect(registry.call("net.cidr_is_valid", [""]).to_ruby).to be(false)
    end

    # Forms IPAddr accepts but OPA/Go reject (verified against opa eval).
    it "is false for a dotted-decimal netmask, scoped, or bracketed address" do
      expect(registry.call("net.cidr_is_valid", ["10.0.0.0/255.0.0.0"]).to_ruby).to be(false)
      expect(registry.call("net.cidr_is_valid", ["10.0.0.0/255.255.255.0"]).to_ruby).to be(false)
      expect(registry.call("net.cidr_is_valid", ["fe80::1%eth0/64"]).to_ruby).to be(false)
      expect(registry.call("net.cidr_is_valid", ["[::1]/128"]).to_ruby).to be(false)
    end

    # net.cidr_is_valid is total over runtime values (matching OPA): a non-string yields
    # false, not undefined (unlike cidr_contains/intersects).
    it "returns false (not undefined) for a non-string argument" do
      [123, true, [1, 2], { "k" => 1 }, nil].each do |arg|
        expect(registry.call("net.cidr_is_valid", [arg]).to_ruby).to be(false)
      end
    end
  end

  # A non-ASCII-compatible encoding (e.g. UTF-16) passes valid_encoding? but makes IPAddr
  # raise a non-IPAddr::Error (Encoding::CompatibilityError). It must not escape: is_valid
  # stays false (total), and contains/intersects yield undefined. Reachable only via the
  # Ruby API (JSON/Rego input is always UTF-8).
  describe "non-ASCII-compatible encoding (Ruby API only)" do
    let(:utf16) { "10.0.0.0/8".encode("UTF-16LE") }

    it "does not escape — is_valid is false, contains/intersects are undefined" do
      expect(registry.call("net.cidr_is_valid", [utf16]).to_ruby).to be(false)
      expect(registry.call("net.cidr_contains", [utf16, "10.0.0.1"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_intersects", [utf16, "10.0.0.0/8"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end
# rubocop:enable Metrics/BlockLength
