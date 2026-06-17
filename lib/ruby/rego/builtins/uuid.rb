# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

module Ruby
  module Rego
    module Builtins
      # UUID parsing (uuid.parse), matching OPA's internal/uuid (a port of google/uuid). The
      # result carries the version and variant for every UUID, plus the decoded time, node id,
      # MAC bits, and clock sequence for the time-based versions 1 and 2 (and the DCE id/domain
      # for version 2). A non-string or an unparseable UUID yields undefined.
      #
      # uuid.rfc4122 is intentionally omitted: it is a per-evaluation random generator (memoized
      # by key, seeded per query). The per-evaluation registry overlay added for time.now_ns
      # (Evaluator#evaluate) is the mechanism to thread that evaluator-scoped state when it lands.
      module Uuid
        extend RegistryHelpers

        # 100ns intervals between the RFC 4122 epoch (1582-10-15) and the Unix epoch.
        EPOCH_100NS = 122_192_928_000_000_000
        # DCE Security (version 2) domain names; an unknown domain renders as "Domain<n>".
        DOMAINS = { 0 => "Person", 1 => "Group", 2 => "Org" }.freeze
        HYPHEN_POSITIONS = [8, 13, 18, 23].freeze
        TIME_BASED_VERSIONS = [1, 2].freeze

        UUID_FUNCTIONS = {
          "uuid.parse" => { arity: 1, handler: :parse }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, UUID_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # Parses a UUID string into its components, or undefined if it is not a valid UUID.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Hash, Ruby::Rego::UndefinedValue]
        def self.parse(value)
          Base.assert_type(value, expected: StringValue, context: "uuid.parse")
          bytes = decode(value.value)
          return UndefinedValue.new unless bytes

          fields(bytes)
        end

        # The 16 bytes of a UUID, or nil if the string is not one. Accepts every google/uuid form:
        # canonical 36-char hyphenated, 32-char unhyphenated, 45-char `urn:uuid:`-prefixed (case-
        # insensitive), and 38-char wrapped — where, matching google/uuid, only the inner 36 chars
        # are read and the outer two (the braces) are not validated.
        # @return [Array[Integer], nil]
        def self.decode(string)
          # Work on a binary copy so length/slicing are byte-oriented, matching google/uuid's
          # byte-length dispatch (a multibyte char makes char-length and byte-length differ).
          hex = canonical_hex(string.b)
          return nil unless hex&.match?(/\A\h{32}\z/)

          [hex].pack("H*").bytes
        end
        private_class_method :decode

        # @return [String, nil]
        # :reek:TooManyStatements
        def self.canonical_hex(string)
          case string.length
          when 32 then string
          when 36 then dehyphenate(string)
          when 38 then dehyphenate(string[1, 36].to_s)
          when 45 then string[0, 9].to_s.downcase == "urn:uuid:" ? dehyphenate(string[9, 36].to_s) : nil
          end
        end
        private_class_method :canonical_hex

        # Removes the four canonical hyphens, requiring them at the RFC 4122 positions; nil if a
        # hyphen is missing there or a stray hyphen elsewhere leaves the result short.
        # @return [String, nil]
        def self.dehyphenate(string)
          return nil unless HYPHEN_POSITIONS.all? { |pos| string[pos] == "-" }

          stripped = string.delete("-")
          stripped.length == 32 ? stripped : nil
        end
        private_class_method :dehyphenate

        # @return [Hash]
        def self.fields(bytes)
          version = bytes[6] >> 4
          out = { "version" => version, "variant" => variant(bytes[8]) }
          out.merge!(time_fields(bytes)) if TIME_BASED_VERSIONS.include?(version)
          out.merge!(dce_fields(bytes)) if version == 2
          out
        end
        private_class_method :fields

        # google/uuid Variant, from the top bits of byte 8.
        # @return [String]
        def self.variant(byte)
          return "RFC4122" if byte & 0xc0 == 0x80

          high = byte & 0xe0
          return "Microsoft" if high == 0xc0
          return "Future" if high == 0xe0

          "Reserved"
        end
        private_class_method :variant

        # @return [Hash]
        def self.time_fields(bytes)
          {
            "time" => unix_nanos(bytes),
            "nodeid" => node_id(bytes),
            "macvariables" => mac_vars(bytes[10]),
            "clocksequence" => uint16(bytes, 8) & 0x3fff
          }
        end
        private_class_method :time_fields

        # @return [Hash]
        def self.dce_fields(bytes)
          domain = bytes[9]
          { "id" => uint32(bytes, 0), "domain" => DOMAINS[domain] || "Domain#{domain}" }
        end
        private_class_method :dce_fields

        # The 60-bit timestamp (100ns ticks since 1582) as nanoseconds since the Unix epoch.
        # The Go sec/nsec split reduces algebraically to ticks-since-epoch * 100, wrapped to a
        # signed 64-bit integer to match OPA's int64 arithmetic (which silently overflows for
        # the extreme — non-real — timestamps near the 60-bit ends).
        # @return [Integer]
        def self.unix_nanos(bytes)
          timestamp = uint32(bytes, 0) | (uint16(bytes, 4) << 32) | ((uint16(bytes, 6) & 0xfff) << 48)
          wrap_int64((timestamp - EPOCH_100NS) * 100)
        end
        private_class_method :unix_nanos

        # @return [Integer]
        # :reek:UncommunicativeMethodName
        def self.wrap_int64(value)
          value &= 0xFFFF_FFFF_FFFF_FFFF
          value >= 0x8000_0000_0000_0000 ? value - 0x1_0000_0000_0000_0000 : value
        end
        private_class_method :wrap_int64

        # @return [String]
        def self.node_id(bytes)
          bytes.last(6).map { |byte| format("%02x", byte) }.join("-")
        end
        private_class_method :node_id

        # google/uuid macVars: the local/global and unicast/multicast bits of the node's first byte.
        # @return [String]
        def self.mac_vars(byte)
          return "local:multicast" if byte & 0b11 == 0b11
          return "global:multicast" if byte & 0b01 == 0b01
          return "local:unicast" if byte & 0b10 == 0b10

          "global:unicast"
        end
        private_class_method :mac_vars

        # @return [Integer]
        # :reek:UncommunicativeMethodName
        def self.uint16(bytes, offset)
          (bytes[offset] << 8) | bytes[offset + 1]
        end
        private_class_method :uint16

        # @return [Integer]
        # :reek:UncommunicativeMethodName
        def self.uint32(bytes, offset)
          (uint16(bytes, offset) << 16) | uint16(bytes, offset + 2)
        end
        private_class_method :uint32
      end
    end
  end
end

Ruby::Rego::Builtins::Uuid.register!
