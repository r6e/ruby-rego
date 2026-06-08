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

    # An IPv4-mapped IPv6 CIDR whose prefix (80..95) cuts through the `::ffff:` marker is a
    # degenerate input: IPAddr masks it to `::/prefix`, so the gem stays self-consistent
    # (a network contains itself). OPA inherits golang/go#51906 here and is non-reflexive
    # (returns false). We keep the reflexive result and document the divergence rather than
    # reproduce the upstream Go inconsistency.
    it "stays reflexive for the degenerate IPv4-mapped /80..95 band (diverges from OPA per go#51906)" do
      expect(registry.call("net.cidr_contains", ["::ffff:10.0.0.0/80", "::ffff:10.0.0.0/80"]).to_ruby).to be(true)
      expect(registry.call("net.cidr_contains", ["::ffff:10.0.0.0/95", "::ffff:10.0.0.0/95"]).to_ruby).to be(true)
      # band edges (/79 below, /96 at/above the ::ffff: marker) match OPA — both reflexive
      expect(registry.call("net.cidr_contains", ["::ffff:10.0.0.0/79", "::ffff:10.0.0.0/79"]).to_ruby).to be(true)
      expect(registry.call("net.cidr_contains", ["::ffff:10.0.0.0/96", "::ffff:10.0.0.0/96"]).to_ruby).to be(true)
    end

    it "accepts a leading-zero prefix length like OPA (/08 == /8)" do
      expect(registry.call("net.cidr_contains", ["10.0.0.0/08", "10.1.2.3"]).to_ruby).to be(true)
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

    it "accepts a leading-zero prefix length like OPA (/08, /008, /00)" do
      expect(registry.call("net.cidr_is_valid", ["10.0.0.0/08"]).to_ruby).to be(true)
      expect(registry.call("net.cidr_is_valid", ["10.0.0.0/008"]).to_ruby).to be(true)
      expect(registry.call("net.cidr_is_valid", ["2001:db8::/00"]).to_ruby).to be(true)
    end

    it "is false for a bare IP (no prefix), bad mask, abbreviated, or garbage" do
      expect(registry.call("net.cidr_is_valid", ["192.168.0.1"]).to_ruby).to be(false)
      expect(registry.call("net.cidr_is_valid", ["10.0.0.0/33"]).to_ruby).to be(false)
      expect(registry.call("net.cidr_is_valid", ["10/8"]).to_ruby).to be(false)
      expect(registry.call("net.cidr_is_valid", ["not-a-cidr"]).to_ruby).to be(false)
      expect(registry.call("net.cidr_is_valid", [""]).to_ruby).to be(false)
      # leading-zero octets (octal-style) are rejected by both IPAddr and OPA/Go
      expect(registry.call("net.cidr_is_valid", ["010.0.0.0/8"]).to_ruby).to be(false)
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

  describe "net.cidr_expand" do
    it "expands a CIDR into the set of its addresses" do
      expect(registry.call("net.cidr_expand", ["192.168.0.0/30"]).to_ruby)
        .to eq(Set["192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3"])
    end

    it "masks host bits to the network before expanding (matching OPA)" do
      expect(registry.call("net.cidr_expand", ["192.168.0.5/30"]).to_ruby)
        .to eq(Set["192.168.0.4", "192.168.0.5", "192.168.0.6", "192.168.0.7"])
    end

    it "expands a /32 to a single address and handles IPv6" do
      expect(registry.call("net.cidr_expand", ["10.0.0.5/32"]).to_ruby).to eq(Set["10.0.0.5"])
      expect(registry.call("net.cidr_expand", ["2001:db8::/126"]).to_ruby)
        .to eq(Set["2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"])
    end

    it "is undefined for a bare IP (a prefix is required), an invalid CIDR, or a non-string" do
      expect(registry.call("net.cidr_expand", ["10.0.0.1"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_expand", ["bad"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_expand", ["192.168.1.0/33"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_expand", [42])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for a block larger than the DoS cap (OPA relies on Go's runtime)" do
      expect(registry.call("net.cidr_expand", ["10.0.0.0/8"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_expand", ["0.0.0.0/0"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "net.cidr_contains_matches" do
    it "returns [index, index] pairs for array operands" do
      expect(registry.call("net.cidr_contains_matches", [["10.0.0.0/8"], ["10.1.1.1", "192.0.0.1"]]).to_ruby)
        .to eq(Set[[0, 0]])
    end

    it "keys each side by its collection type (object key, set element, or the scalar)" do
      expect(registry.call("net.cidr_contains_matches", [{ "a" => "10.0.0.0/8" }, { "x" => "10.1.1.1" }]).to_ruby)
        .to eq(Set[%w[a x]])
      expect(registry.call("net.cidr_contains_matches", [Set["10.0.0.0/8"], "10.1.1.1"]).to_ruby)
        .to eq(Set[["10.0.0.0/8", "10.1.1.1"]])
      expect(registry.call("net.cidr_contains_matches", ["10.0.0.0/8", "10.1.1.1"]).to_ruby)
        .to eq(Set[["10.0.0.0/8", "10.1.1.1"]])
    end

    it "returns the full cross-product of matches" do
      result = registry.call("net.cidr_contains_matches",
                             [["10.0.0.0/8", "192.168.0.0/16"], ["10.1.1.1", "192.168.5.5"]]).to_ruby
      expect(result).to eq(Set[[0, 0], [1, 1]])
    end

    it "is an empty set when nothing matches or the collection is empty" do
      expect(registry.call("net.cidr_contains_matches", [[], "10.1.1.1"]).to_ruby).to eq(Set.new)
    end

    it "is an empty set when either operand is empty, with no value-parsing (OPA)" do
      expect(registry.call("net.cidr_contains_matches", [[], ["bad"]]).to_ruby).to eq(Set.new)
      expect(registry.call("net.cidr_contains_matches", [[], [42]]).to_ruby).to eq(Set.new)
      expect(registry.call("net.cidr_contains_matches", [["bad-cidr"], []]).to_ruby).to eq(Set.new)
      expect(registry.call("net.cidr_contains_matches", [["10.0.0.1"], []]).to_ruby).to eq(Set.new)
    end

    it "still structurally checks cidr-side elements when addresses is empty (OPA)" do
      # A non-string / empty-array cidr-side element is undefined even with no addresses,
      # but a non-empty array (whose contents are only value-checked later) is an empty set.
      expect(registry.call("net.cidr_contains_matches", [[42], []])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_contains_matches", [[[]], []])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_contains_matches", [[[42]], []]).to_ruby).to eq(Set.new)
    end

    it "accepts [address, metadata] tuples, taking the first element and keying by position" do
      expect(registry.call("net.cidr_contains_matches", [[["10.0.0.0/8", "m"]], ["10.1.1.1"]]).to_ruby)
        .to eq(Set[[0, 0]])
      expect(registry.call("net.cidr_contains_matches", [["10.0.0.0/8"], [["10.1.1.1", "m"]]]).to_ruby)
        .to eq(Set[[0, 0]])
      expect(registry.call("net.cidr_contains_matches", [{ "k" => ["10.0.0.0/8", "m"] }, "10.1.1.1"]).to_ruby)
        .to eq(Set[["k", "10.1.1.1"]])
    end

    it "is undefined for a non-string/empty-array address-side element (even with a valid network)" do
      expect(registry.call("net.cidr_contains_matches", [["10.0.0.0/8"], [42]]))
        .to be_a(Ruby::Rego::UndefinedValue)
      # A non-matching network still validates the address side eagerly (matching OPA).
      expect(registry.call("net.cidr_contains_matches", [["99.0.0.0/8"], [42]]))
        .to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_contains_matches", [["10.0.0.0/8"], [[]]]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined for an empty-array element or one whose first element is not an address" do
      expect(registry.call("net.cidr_contains_matches", [[[]], "10.1.1.1"])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_contains_matches", [[%w[bad x]], "10.1.1.1"]))
        .to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_contains_matches", [[[["10.0.0.0/8"]]], "10.1.1.1"]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined if any element is non-string, an unparseable address, or a bare-IP cidr-side" do
      expect(registry.call("net.cidr_contains_matches", [["10.0.0.0/8", "bad"], "10.1.1.1"]))
        .to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_contains_matches", [["10.0.0.0/8"], ["10.1.1.1", "bad"]]))
        .to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_contains_matches", [["10.0.0.0/8", 42], "10.1.1.1"]))
        .to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_contains_matches", ["10.0.0.1", "10.0.0.1"]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end
  end

  describe "net.cidr_merge" do
    def merge(arr)
      registry.call("net.cidr_merge", [arr]).to_ruby.to_a.sort
    end

    it "merges adjacent subnets and absorbs contained ones" do
      expect(merge(["192.168.0.0/24", "192.168.1.0/24"])).to eq(["192.168.0.0/23"])
      expect(merge(["10.0.0.0/8", "10.1.0.0/16"])).to eq(["10.0.0.0/8"])
      expect(merge(["192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"]))
        .to eq(["192.168.0.0/22"])
    end

    it "keeps disjoint networks and sorts the result, masking CIDRs to their network" do
      expect(merge(["192.168.0.0/24", "10.0.0.0/8"])).to eq(["10.0.0.0/8", "192.168.0.0/24"])
      expect(merge(["192.168.1.5/24"])).to eq(["192.168.1.0/24"])
      expect(merge(["10.0.0.0/24", "10.0.1.0/25"])).to eq(["10.0.0.0/24", "10.0.1.0/25"])
    end

    it "accepts a set operand and an empty list" do
      expect(registry.call("net.cidr_merge", [Set["192.168.0.0/24", "192.168.1.0/24"]]).to_ruby)
        .to eq(Set["192.168.0.0/23"])
      expect(registry.call("net.cidr_merge", [[]]).to_ruby).to eq(Set.new)
    end

    it "gives a bare IPv4 its classful mask, unmasked unless merged" do
      expect(merge(["1.1.1.1"])).to eq(["1.1.1.1/8"])           # class A, untouched -> host kept
      expect(merge(["192.168.5.7"])).to eq(["192.168.5.7/24"])  # class C
      expect(merge(["1.1.1.1", "1.1.1.2"])).to eq(["1.0.0.0/8"]) # overlap -> merged -> masked
    end

    it "merges IPv6 and renders RFC 5952 form" do
      expect(merge(["2001:db8::/34", "2001:db8:4000::/34", "2001:db8:8000::/33"])).to eq(["2001:db8::/32"])
      expect(merge(["::/0"])).to eq(["::/0"])
      expect(merge(["::1.2.3.4/126"])).to eq(["::102:304/126"]) # no deprecated ::a.b.c.d form
    end

    it "absorbs IPv4 into a containing IPv6 range (v4 lives in the ::ffff: block), matching OPA" do
      expect(merge(["192.168.0.0/24", "2001:db8::/32"])).to eq(["192.168.0.0/24", "2001:db8::/32"])
      expect(merge(["::/0", "10.0.0.0/8"])).to eq(["::/0"]) # ::/0 covers the ::ffff: block
      expect(merge(["::/1", "10.0.0.0/8"])).to eq(["::/1"])
      expect(merge(["8000::/1", "10.0.0.0/8"])).to eq(["10.0.0.0/8", "8000::/1"]) # upper half: no overlap
    end

    it "renders each output CIDR's family at the ::ffff: boundary (per-CIDR, like OPA)" do
      # A range straddling the v4-mapped block edge decomposes into a v4 block (rendered dotted)
      # and a v6 block (rendered hex), each by its own family (verified vs opa eval).
      expect(merge(["0.0.0.0/32", "::fffe:ffff:ffff/128"]))
        .to eq(["0.0.0.0/32", "::fffe:ffff:ffff/128"])
    end

    it "is undefined for a bare IPv6, an invalid element, or a non-collection operand" do
      expect(registry.call("net.cidr_merge", [["2001:db8::"]])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_merge", [["01.1.1.1/24"]])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_merge", [["10.0.0.0/33"]])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_merge", [[42]])).to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("net.cidr_merge", ["192.168.0.0/24"])).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "is undefined (not a raised error) for a non-ASCII-compatible string element" do
      element = Ruby::Rego::StringValue.new("10.0.0.0/8".encode("UTF-16LE"))
      result = registry.call("net.cidr_merge", [Ruby::Rego::ArrayValue.new([element])])

      expect(result).to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end
# rubocop:enable Metrics/BlockLength
