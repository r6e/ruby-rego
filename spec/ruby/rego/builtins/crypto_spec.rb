# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength
RSpec.describe "crypto builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }

  describe "crypto.md5" do
    it "returns the hex MD5 digest" do
      expect(registry.call("crypto.md5", ["abc"]).to_ruby).to eq("900150983cd24fb0d6963f7d28e17f72")
    end
  end

  describe "crypto.sha1" do
    it "returns the hex SHA-1 digest" do
      expect(registry.call("crypto.sha1", ["abc"]).to_ruby).to eq("a9993e364706816aba3e25717850c26c9cd0d89d")
    end
  end

  describe "crypto.sha256" do
    it "returns the hex SHA-256 digest" do
      expect(registry.call("crypto.sha256", ["abc"]).to_ruby)
        .to eq("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    end

    it "hashes the empty string" do
      expect(registry.call("crypto.sha256", [""]).to_ruby)
        .to eq("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    end

    it "hashes the UTF-8 bytes of a multibyte string (matching OPA)" do
      expect(registry.call("crypto.sha256", ["café"]).to_ruby)
        .to eq("850f7dc43910ff890f8879c0ed26fe697c93a067ad93a7d50f466a7028a9bf4e")
    end
  end

  it "is undefined for a non-string argument" do
    expect(registry.call("crypto.md5", [123])).to be_a(Ruby::Rego::UndefinedValue)
    expect(registry.call("crypto.sha256", [["x"]])).to be_a(Ruby::Rego::UndefinedValue)
  end
end
# rubocop:enable Metrics/BlockLength
