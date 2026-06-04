# frozen_string_literal: true

require "timeout"

# rubocop:disable Metrics/BlockLength
# Expected values verified against `opa eval` 1.17 via the runtime (input-driven) path,
# except where noted as an intentional divergence from an upstream OPA bug.
RSpec.describe "semver builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  def valid?(version)
    registry.call("semver.is_valid", [version]).to_ruby
  end

  def compare(left, right)
    result = registry.call("semver.compare", [left, right])
    result.is_a?(Ruby::Rego::UndefinedValue) ? :undef : result.to_ruby
  end

  describe "semver.is_valid" do
    it "accepts well-formed versions (core, prerelease, build)" do
      expect(valid?("1.2.3")).to be(true)
      expect(valid?("0.0.0")).to be(true)
      expect(valid?("1.0.0-alpha.1")).to be(true)
      expect(valid?("1.0.0+20130313144700")).to be(true)
      expect(valid?("1.0.0-alpha+build")).to be(true)
    end

    it "is lenient like OPA: leading v, leading zeros, empty prerelease/build" do
      expect(valid?("v1.2.3")).to be(true)
      expect(valid?("01.2.3")).to be(true)
      expect(valid?("1.00.0")).to be(true)
      expect(valid?("1.0.0-01")).to be(true)
      expect(valid?("1.0.0-")).to be(true)
      expect(valid?("1.0.0+")).to be(true)
    end

    it "rejects malformed versions" do
      expect(valid?("1.2")).to be(false)
      expect(valid?("1.2.3.4")).to be(false)
      expect(valid?("V1.2.3")).to be(false)
      expect(valid?("")).to be(false)
      expect(valid?("1.0.0-alpha.")).to be(false)
      expect(valid?("1.0.0-alpha..1")).to be(false)
      expect(valid?("1.0.0+a_b")).to be(false)
      expect(valid?(" 1.2.3")).to be(false)
    end

    it "bounds numeric components to a signed 64-bit integer (matching OPA)" do
      expect(valid?("9223372036854775807.0.0")).to be(true)  # 2**63 - 1
      expect(valid?("9223372036854775808.0.0")).to be(false) # 2**63
      expect(valid?("9999999999999999999.0.0")).to be(false) # > 2**63 - 1
    end

    it "is total over runtime values: a non-string yields false" do
      [123, true, [1, 2], { "k" => 1 }, nil].each do |arg|
        expect(valid?(arg)).to be(false)
      end
    end
  end

  describe "semver.compare" do
    it "compares core versions numerically" do
      expect(compare("1.0.0", "2.0.0")).to eq(-1)
      expect(compare("1.2.3", "1.2.3")).to eq(0)
      expect(compare("1.10.0", "1.9.0")).to eq(1)
    end

    it "orders a prerelease below its release and by SemVer precedence" do
      expect(compare("1.0.0-alpha", "1.0.0")).to eq(-1)
      expect(compare("1.0.0-alpha", "1.0.0-beta")).to eq(-1)
      expect(compare("1.0.0-alpha.1", "1.0.0-alpha.2")).to eq(-1)
      expect(compare("1.0.0-1", "1.0.0-alpha")).to eq(-1) # numeric ids rank below alphanumeric
      expect(compare("1.0.0-alpha", "1.0.0-alpha.1")).to eq(-1) # smaller set < larger set
    end

    it "ignores build metadata and strips v / leading zeros" do
      expect(compare("1.0.0+build1", "1.0.0+build2")).to eq(0)
      expect(compare("v1.2.3", "1.2.3")).to eq(0)
      expect(compare("1.00.0", "1.0.0")).to eq(0)
    end

    it "is undefined for a non-string or invalid version" do
      expect(compare(7, "1.2.3")).to eq(:undef)
      expect(compare("1.2.3", "garbage")).to eq(:undef)
      expect(compare("1.2", "1.2.3")).to eq(:undef)
    end

    # Intentional divergence: OPA's semver.compare infinite-loops when two numeric
    # prerelease identifiers are equal in value but differ textually via leading zeros
    # (upstream coreos/go-semver bug). The gem compares them numerically (equal),
    # terminates, and returns the correct SemVer result (0).
    it "returns the correct result without hanging on leading-zero-equal prereleases" do
      result = nil
      expect do
        Timeout.timeout(5) do
          result = [
            compare("1.0.0-01", "1.0.0-1"),
            compare("1.0.0-0", "1.0.0-00"),
            compare("1.0.0-alpha.01", "1.0.0-alpha.1")
          ]
        end
      end.not_to raise_error
      expect(result).to eq([0, 0, 0])
    end
  end
end
# rubocop:enable Metrics/BlockLength
