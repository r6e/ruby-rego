# frozen_string_literal: true

require "base64"
require "openssl"

module Ruby
  module Rego
    module Builtins
      module Crypto
        # Public-key field of the certificate struct (see certificate_struct.rb for the module role).
        module CertificateStruct
          # The PublicKey field, matching Go's json.Marshal of the concrete public-key type: an
          # rsa.PublicKey is {N, E}; an ecdsa.PublicKey is {Curve:{}, X, Y}; an ed25519.PublicKey is
          # the std-base64 of its 32 bytes.
          def self.public_key(cert)
            key = cert.public_key
            case key.oid
            when "id-ecPublicKey" then ec_public_key(key)
            when "ED25519" then Base64.strict_encode64(key.raw_public_key)
            else { "N" => key.n.to_i, "E" => key.e.to_i }
            end
          end

          # :reek:UncommunicativeVariableName -- x/y are the standard names for EC point coordinates.
          def self.ec_public_key(key)
            width = (key.group.degree + 7) / 8
            encoded = key.public_key.to_bn(:uncompressed).to_s(2)
            x = OpenSSL::BN.new(encoded[1, width].to_s, 2).to_i
            y = OpenSSL::BN.new(encoded[1 + width, width].to_s, 2).to_i
            { "Curve" => {}, "X" => x, "Y" => y }
          end
          private_class_method :ec_public_key
        end
      end
    end
  end
end
