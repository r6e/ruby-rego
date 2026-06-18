# frozen_string_literal: true

require "json"
require "timeout"

# crypto.parse_private_keys / crypto.x509.parse_rsa_private_key — OpenSSL-backed private-key
# parsers. Every expected value is captured byte-for-byte from `opa eval` 1.17 (goldens.json)
# against committed throwaway test keys spanning every supported and unsupported key type, so the
# suite measures real OPA compatibility. Edge inputs are stored with their expected values in the
# golden file so the two can never drift apart.
# rubocop:disable Metrics/BlockLength
RSpec.describe "crypto private-key builtins" do
  let(:registry) { Ruby::Rego::Builtins::BuiltinRegistry.instance }
  fixtures = File.expand_path("../../../fixtures/crypto_keys", __dir__)
  goldens = JSON.parse(File.read(File.join(fixtures, "goldens.json")))

  # goldens.json marks an undefined OPA result with this sentinel (JSON cannot represent "absent");
  # a literal null in a golden is a real Rego null, distinct from undefined.
  undef_sentinel = "__undef__"

  resolve = lambda do |registry, fn, string|
    result = registry.call(fn, [Ruby::Rego::StringValue.new(string)])
    result.is_a?(Ruby::Rego::UndefinedValue) ? undef_sentinel : result.to_ruby
  end

  describe "crypto.parse_private_keys (PEM private keys -> Go-struct array)" do
    goldens.fetch("keys_ppk").each do |name, expected|
      it "matches OPA on the #{name} key fixture" do
        pem = File.read(File.join(fixtures, "#{name}.pem"))
        expect(resolve.call(registry, "crypto.parse_private_keys", pem)).to eq(expected)
      end
    end

    goldens.fetch("edges_ppk").each do |name, expected|
      it "matches OPA on the #{name} edge case" do
        input = goldens.fetch("edge_inputs").fetch(name)
        expect(resolve.call(registry, "crypto.parse_private_keys", input)).to eq(expected)
      end
    end
  end

  describe "crypto.x509.parse_rsa_private_key (PEM/base64 private key -> JWK)" do
    goldens.fetch("keys_prk").each do |name, expected|
      it "matches OPA on the #{name} key fixture" do
        pem = File.read(File.join(fixtures, "#{name}.pem"))
        expect(resolve.call(registry, "crypto.x509.parse_rsa_private_key", pem)).to eq(expected)
      end
    end

    goldens.fetch("edges_prk").each do |name, expected|
      it "matches OPA on the #{name} edge case" do
        input = goldens.fetch("edge_inputs").fetch(name)
        expect(resolve.call(registry, "crypto.x509.parse_rsa_private_key", input)).to eq(expected)
      end
    end
  end

  describe "totality and type handling" do
    # Build a PEM block from a label and raw DER bytes (64-col base64 body).
    def block(label, der)
      "-----BEGIN #{label}-----\n#{[der].pack("m0").scan(/.{1,64}/).join("\n")}\n-----END #{label}-----\n"
    end

    it "is undefined for a non-string argument (both functions)" do
      [42, true, [1], { "a" => 1 }].each do |bad|
        arg = [Ruby::Rego::Value.from_ruby(bad)]
        expect(registry.call("crypto.parse_private_keys", arg)).to be_a(Ruby::Rego::UndefinedValue)
        expect(registry.call("crypto.x509.parse_rsa_private_key", arg)).to be_a(Ruby::Rego::UndefinedValue)
      end
    end

    it "distinguishes null (empty input) from undefined (no key found)" do
      # parse_private_keys("") is a Rego null; parse_rsa_private_key("") is undefined.
      expect(registry.call("crypto.parse_private_keys", [Ruby::Rego::StringValue.new("")]))
        .to be_a(Ruby::Rego::NullValue)
      expect(registry.call("crypto.x509.parse_rsa_private_key", [Ruby::Rego::StringValue.new("")]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "does not raise on an unsupported key type (DSA/Ed448/X448/secp256k1) — returns undefined" do
      %w[dsa ed448 x448 secp256k1].each do |name|
        pem = File.read(File.join(fixtures, "#{name}.pem"))
        %w[crypto.parse_private_keys crypto.x509.parse_rsa_private_key].each do |fn|
          arg = [Ruby::Rego::StringValue.new(pem)]
          expect { registry.call(fn, arg) }.not_to raise_error
          expect(registry.call(fn, arg)).to be_a(Ruby::Rego::UndefinedValue)
        end
      end
    end

    it "is undefined (not a crash or a zeroed struct) for a public key in a PRIVATE KEY block" do
      # OpenSSL.read is label-tolerant; a public key smuggled into a private-key block has no private
      # material. OPA (Go x509) rejects it -> undefined; the gem must not crash or emit a fake key.
      %w[rsa_pkcs8 ec_p256 ed25519].each do |name|
        key = OpenSSL::PKey.read(File.read(File.join(fixtures, "#{name}.pem")))
        pem = block("PRIVATE KEY", key.public_to_der)
        %w[crypto.parse_private_keys crypto.x509.parse_rsa_private_key].each do |fn|
          arg = [Ruby::Rego::StringValue.new(pem)]
          expect { registry.call(fn, arg) }.not_to raise_error
          expect(registry.call(fn, arg)).to be_a(Ruby::Rego::UndefinedValue)
        end
      end
    end

    # The PEM scanner is a port of Go's O(n^2)-in-theory pem.Decode loop, but the realistic DoS
    # vectors (many BEGIN markers that never close) must stay linear, like OPA. Each of these is
    # ~700KB and would take tens of seconds quadratically.
    begins = "-----BEGIN PRIVATE KEY-----\n" * 25_000
    begins_with_bodies = "-----BEGIN PRIVATE KEY-----\nAAAA!\n" * 20_000
    huge_body = "A" * (4 * 1024 * 1024)
    huge_block = "-----BEGIN RSA PRIVATE KEY-----\n#{huge_body}\n-----END RSA PRIVATE KEY-----\n"
    {
      "no END at all (fast-path guard)" => "-----BEGIN X-----\n" * 40_000,
      "non-line-anchored END" => "#{begins}ZZZ-----END PRIVATE KEY-----",
      "valid-base64-prefix bodies, far shared END" => "#{begins_with_bodies}-----END PRIVATE KEY-----\n",
      "a huge all-base64 body (DER size cap)" => huge_block
    }.each do |label, evil|
      it "scans #{label} linearly (DoS guard)" do
        arg = [Ruby::Rego::StringValue.new(evil)]
        expect { Timeout.timeout(5) { registry.call("crypto.parse_private_keys", arg) } }.not_to raise_error
      end
    end

    it "does not raise on a non-UTF-8 or ASCII-incompatible argument" do
      [(+"\xFF\xFE").force_encoding("UTF-8"), "key".encode("UTF-16LE")].each do |bad|
        arg = [Ruby::Rego::StringValue.new(bad)]
        expect { registry.call("crypto.parse_private_keys", arg) }.not_to raise_error
        expect { registry.call("crypto.x509.parse_rsa_private_key", arg) }.not_to raise_error
      end
    end

    it "dispatches by block type — a DER in the wrong format for its label is undefined (matches OPA)" do
      rsa = OpenSSL::PKey::RSA.new(2048)
      ec = OpenSSL::PKey::EC.generate("prime256v1")
      # PKCS#8 DER mislabelled as PKCS#1, and PKCS#1 mislabelled as PKCS#8 — Go's typed parsers reject.
      expect(registry.call("crypto.parse_private_keys",
                           [Ruby::Rego::StringValue.new(block("RSA PRIVATE KEY", rsa.private_to_der))]))
        .to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("crypto.parse_private_keys",
                           [Ruby::Rego::StringValue.new(block("PRIVATE KEY", rsa.to_der))]))
        .to be_a(Ruby::Rego::UndefinedValue)
      expect(registry.call("crypto.parse_private_keys",
                           [Ruby::Rego::StringValue.new(block("EC PRIVATE KEY", ec.private_to_der))]))
        .to be_a(Ruby::Rego::UndefinedValue)
      # correctly-labelled still parse
      expect(registry.call("crypto.parse_private_keys",
                           [Ruby::Rego::StringValue.new(block("PRIVATE KEY", rsa.private_to_der))]))
        .to be_a(Ruby::Rego::ArrayValue)
    end

    it "does not overflow the stack on a deeply-nested ASN.1 body, even on a small-stack thread" do
      # OpenSSL::ASN1.decode recurses with no depth limit; a deeply-nested DER under the size cap
      # must not raise SystemStackError out of the builtin (it would escape the registry's rescue).
      # ~15000 levels (~60 KB, just under the 64 KiB cap) overflows even a generous thread stack.
      nested = "\x30\x00".b
      15_000.times { nested = "#{"\x30\x82".b}#{[nested.bytesize].pack("n")}#{nested}" }
      arg = [Ruby::Rego::StringValue.new(block("EC PRIVATE KEY", nested))]
      result = Thread.new do
        Thread.current.report_on_exception = false
        registry.call("crypto.parse_private_keys", arg)
      end
      expect(result.value).to be_a(Ruby::Rego::UndefinedValue)
    end

    it "rejects a non-minimal DER length encoding, as Go's asn1 does" do
      der = OpenSSL::PKey::RSA.new(2048).private_to_der
      # outer SEQUENCE uses 2-byte long form (0x82 LL LL); rewrite with a superfluous leading zero.
      raise "unexpected length form" unless der.getbyte(1) == 0x82

      non_minimal = "#{"\x30\x83\x00".b}#{der[2, 2]}#{der[4..]}"
      pem = block("PRIVATE KEY", non_minimal)
      expect(registry.call("crypto.parse_private_keys", [Ruby::Rego::StringValue.new(pem)]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end

    it "applies Go's per-format trailing-data rule (PKCS8/EC ignore it, PKCS1 rejects it)" do
      rsa = OpenSSL::PKey::RSA.new(2048)
      trailing = "\x00" * 100
      pkcs8 = block("PRIVATE KEY", rsa.private_to_der + trailing)
      pkcs1 = block("RSA PRIVATE KEY", rsa.to_der + trailing)
      # PKCS#8 with trailing parses (and a huge trailing stays fast — bounded to the leading element).
      expect(registry.call("crypto.parse_private_keys", [Ruby::Rego::StringValue.new(pkcs8)])).to be_a(Ruby::Rego::ArrayValue)
      huge = block("PRIVATE KEY", rsa.private_to_der + ("\x00" * (4 * 1024 * 1024)))
      expect do
        Timeout.timeout(5) { registry.call("crypto.parse_private_keys", [Ruby::Rego::StringValue.new(huge)]) }
      end.not_to raise_error
      # PKCS#1 rejects trailing, matching OPA.
      expect(registry.call("crypto.parse_private_keys", [Ruby::Rego::StringValue.new(pkcs1)]))
        .to be_a(Ruby::Rego::UndefinedValue)
    end
  end
end
# rubocop:enable Metrics/BlockLength
