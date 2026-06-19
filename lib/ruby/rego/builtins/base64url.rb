# frozen_string_literal: true

require "base64"

module Ruby
  module Rego
    module Builtins
      # URL-safe base64 decoding shared by base64url.decode and io.jwt.decode's segments, matching Go's
      # base64.URLEncoding: missing '=' padding is restored, but the standard-base64 '+'/'/' alphabet and
      # a non-canonical '=' (one that doesn't complete a 4-char block) are rejected so a string OPA
      # returns undefined for stays un-decodable. strict_decode raises ArgumentError on rejected input;
      # callers map that to undefined.
      #
      # Gem-more-strict divergence (safe direction, crafted input only): Base64.urlsafe_decode64 strict-
      # decodes, rejecting a final base64url character whose unused low bits are non-zero (e.g. a 2-char
      # "AB"), whereas Go masks those bits and decodes. The gem is undefined where OPA would decode;
      # canonical encoders never emit such input, so real values are unaffected.
      module Base64Url
        # @param string [String]
        # @return [String] the decoded bytes
        # @raise [ArgumentError] when the string is not canonical URL-safe base64
        def self.strict_decode(string)
          raise ArgumentError, "standard base64 character" if string.match?(%r{[+/]})

          Base64.urlsafe_decode64(restore_padding(string))
        end

        # Restores '=' padding so unpadded URL-safe base64 decodes. A string that already carries '=' is
        # left untouched, so a non-canonical pad (e.g. one '=' short of a 4-char block) stays
        # un-decodable, matching Go: padding the length out would otherwise decode a string OPA rejects.
        #
        # @param string [String]
        # @return [String]
        def self.restore_padding(string)
          return string if string.end_with?("=")

          remainder = string.length % 4
          remainder.zero? ? string : string + ("=" * (4 - remainder))
        end
        private_class_method :restore_padding
      end
    end
  end
end
