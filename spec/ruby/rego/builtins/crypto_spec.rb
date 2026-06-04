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

  # HMAC vectors below were verified against `opa eval` 1.17 with message="hello",
  # key="secret". message != key so a swapped-argument bug would change the digest
  # (HMAC is not symmetric in its two arguments).
  describe "crypto.hmac.md5" do
    it "returns the hex HMAC-MD5 of (message, key)" do
      expect(registry.call("crypto.hmac.md5", %w[hello secret]).to_ruby)
        .to eq("bade63863c61ed0b3165806ecd6acefc")
    end
  end

  describe "crypto.hmac.sha1" do
    it "returns the hex HMAC-SHA1 of (message, key)" do
      expect(registry.call("crypto.hmac.sha1", %w[hello secret]).to_ruby)
        .to eq("5112055c05f944f85755efc5cd8970e194e9f45b")
    end
  end

  describe "crypto.hmac.sha256" do
    it "returns the hex HMAC-SHA256 of (message, key)" do
      expect(registry.call("crypto.hmac.sha256", %w[hello secret]).to_ruby)
        .to eq("88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b")
    end

    it "accepts an empty key" do
      expect(registry.call("crypto.hmac.sha256", ["hello", ""]).to_ruby)
        .to eq("4352b26e33fe0d769a8922a6ba29004109f01688e26acc9e6cb347e5a5afc4da")
    end

    it "is order-sensitive in (message, key) — swapping changes the digest" do
      forward = registry.call("crypto.hmac.sha256", %w[hello secret]).to_ruby
      swapped = registry.call("crypto.hmac.sha256", %w[secret hello]).to_ruby
      expect(forward).not_to eq(swapped)
    end
  end

  describe "crypto.hmac.sha512" do
    it "returns the hex HMAC-SHA512 of (message, key)" do
      expect(registry.call("crypto.hmac.sha512", %w[hello secret]).to_ruby)
        .to eq("db1595ae88a62fd151ec1cba81b98c39df82daae7b4cb9820f446d5bf02f1dcfca6683d88cab3e273f5963ab8" \
               "ec469a746b5b19086371239f67d1e5f99a79440")
    end
  end

  it "is undefined for a non-string HMAC message or key" do
    expect(registry.call("crypto.hmac.sha256", [123, "k"])).to be_a(Ruby::Rego::UndefinedValue)
    expect(registry.call("crypto.hmac.sha256", ["m", ["k"]])).to be_a(Ruby::Rego::UndefinedValue)
  end

  describe "crypto.hmac.equal" do
    it "returns true for equal strings and false otherwise (matching OPA)" do
      expect(registry.call("crypto.hmac.equal", %w[abc abc]).to_ruby).to be(true)
      expect(registry.call("crypto.hmac.equal", %w[abc abd]).to_ruby).to be(false)
    end

    it "returns false for different-length strings" do
      expect(registry.call("crypto.hmac.equal", %w[abc abcd]).to_ruby).to be(false)
    end

    it "returns true for two empty strings" do
      expect(registry.call("crypto.hmac.equal", ["", ""]).to_ruby).to be(true)
    end

    it "is undefined for a non-string argument" do
      expect(registry.call("crypto.hmac.equal", [1, "a"])).to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end
# rubocop:enable Metrics/BlockLength
