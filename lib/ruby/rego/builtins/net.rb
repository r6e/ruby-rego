# frozen_string_literal: true

require "ipaddr"
require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

module Ruby
  module Rego
    module Builtins
      # Built-in CIDR helpers (net.cidr_contains, net.cidr_intersects, net.cidr_is_valid),
      # backed by Ruby's IPAddr. A "cidr" is an address with a prefix length (the `/n`
      # suffix is required — a bare IP is not a cidr); host bits beyond the prefix are
      # masked off. cidr_contains/cidr_intersects yield undefined for a non-string or
      # invalid argument, matching OPA; cidr_is_valid is total over runtime values (a
      # non-string yields false, like regex.is_valid). Addresses are parsed by IPAddr,
      # which is linear in the input length, so there is no unbounded cost.
      #
      # Parsing is reconciled with OPA/Go: forms IPAddr accepts but OPA rejects (a
      # dotted-decimal netmask, a scoped `%zone` or bracketed `[..]` address) are rejected,
      # and a leading-zero prefix length (`/08`) is accepted as `/8` (IPAddr rejects it, OPA
      # accepts). One intentional divergence remains: an IPv4-mapped IPv6 CIDR whose prefix
      # falls in 80..95 cuts through the `::ffff:` marker — a degenerate input where OPA
      # inherits golang/go#51906 and cidr_contains is non-reflexive. The gem masks such an
      # input to `::/prefix` and stays reflexive (a network contains itself) rather than
      # reproduce the upstream Go inconsistency. Prefixes >= 96 (genuine mapped addresses)
      # are normalised to native IPv4 to match OPA.
      module Net
        extend RegistryHelpers

        NET_FUNCTIONS = {
          "net.cidr_contains" => { arity: 2, handler: :cidr_contains },
          "net.cidr_intersects" => { arity: 2, handler: :cidr_intersects },
          "net.cidr_is_valid" => { arity: 1, handler: :cidr_is_valid }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, NET_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # True when `cidr` (a CIDR) contains `other` (an IP or CIDR). Undefined if `cidr`
        # is not a valid CIDR, `other` is not a valid IP/CIDR, or either is non-string.
        #
        # @param cidr_value [Ruby::Rego::Value]
        # @param other_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.cidr_contains(cidr_value, other_value)
          cidr = normalize(cidr_arg(cidr_value, "net.cidr_contains"))
          other = normalize(addr_arg(other_value, "net.cidr_contains"))
          BooleanValue.new(cidr.include?(other))
        end

        # True when the two CIDRs overlap. Aligned CIDR blocks are either nested or
        # disjoint, so they intersect iff one contains the other. Both arguments must be
        # valid CIDRs (a bare IP is undefined), matching OPA.
        #
        # @param cidr1_value [Ruby::Rego::Value]
        # @param cidr2_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        def self.cidr_intersects(cidr1_value, cidr2_value)
          first = normalize(cidr_arg(cidr1_value, "net.cidr_intersects"))
          second = normalize(cidr_arg(cidr2_value, "net.cidr_intersects"))
          BooleanValue.new(first.include?(second) || second.include?(first))
        end

        # True when `value` is a string in valid CIDR notation (prefix length required).
        # Total over runtime values: a non-string yields false, matching OPA.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        # :reek:NilCheck
        def self.cidr_is_valid(value)
          return BooleanValue.new(false) unless value.is_a?(StringValue)

          BooleanValue.new(!parse_cidr(value.value).nil?)
        end

        # Parses a CIDR argument (prefix length required); raises (→ undefined) for a
        # non-string or an address that is not valid CIDR notation.
        #
        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [IPAddr]
        def self.cidr_arg(value, context)
          parse_cidr(string_value(value, context)) || raise_invalid_addr(context)
        end
        private_class_method :cidr_arg

        # Parses an IP-or-CIDR argument (prefix length optional); raises (→ undefined) for
        # a non-string or an unparseable address.
        #
        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [IPAddr]
        def self.addr_arg(value, context)
          parse_addr(string_value(value, context)) || raise_invalid_addr(context)
        end
        private_class_method :addr_arg

        # Parses a CIDR (a prefix length must be present); nil otherwise. Delegates address
        # validation to parse_addr, then requires the `/` — checked only after parse_addr
        # succeeds, so `string` is known ASCII-compatible before `include?` runs.
        #
        # @param string [String]
        # @return [IPAddr, nil]
        def self.parse_cidr(string)
          addr = parse_addr(string)
          addr if addr && string.include?("/")
        end
        private_class_method :parse_cidr

        # Parses an IP or CIDR with IPAddr, returning nil for any input OPA would reject.
        # Beyond IPAddr's own validation (rescued via IPAddr::Error), forms IPAddr handles
        # differently from OPA/Go are reconciled first: a non-ASCII-compatible or
        # invalid-encoding string (which would make IPAddr raise a bare ArgumentError, not
        # IPAddr::Error) and a scoped/zone (`%`) or bracketed (`[]`) address are rejected,
        # and the prefix length is canonicalised by `canonical_source`.
        #
        # @param string [String]
        # @return [IPAddr, nil]
        def self.parse_addr(string)
          return nil unless string.encoding.ascii_compatible? && string.valid_encoding?
          return nil if string.match?(/[%\[\]]/)

          source = canonical_source(string)

          IPAddr.new(source) if source
        rescue IPAddr::Error
          nil
        end
        private_class_method :parse_addr

        # Reconciles the `/prefix` suffix with OPA/Go before handing it to IPAddr: returns
        # nil when the suffix is non-integer (a dotted-decimal netmask, which OPA rejects),
        # and strips leading zeros otherwise (OPA accepts `/08` as `/8`, but IPAddr rejects
        # a leading-zero prefix). A string without a prefix is returned unchanged.
        #
        # @param string [String]
        # @return [String, nil]
        def self.canonical_source(string)
          return string unless string.include?("/")

          addr, prefix = string.split("/", 2)
          return nil unless prefix&.match?(/\A\d+\z/)

          "#{addr}/#{prefix.to_i}"
        end
        private_class_method :canonical_source

        # Normalizes an IPv4-mapped IPv6 address (e.g. `::ffff:10.0.0.0/120`) to its native
        # IPv4 form so cross-notation comparisons match OPA, which treats the mapped and
        # bare-IPv4 forms as equal. `ipv4_mapped?` is true only when the prefix covers the
        # whole `::ffff:` (>= 96); below that OPA keeps it IPv6, and so do we (no-op).
        #
        # @param addr [IPAddr]
        # @return [IPAddr]
        def self.normalize(addr)
          addr.ipv4_mapped? ? addr.native : addr
        end
        private_class_method :normalize

        # @param context [String]
        # @return [void]
        def self.raise_invalid_addr(context)
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Invalid CIDR or address",
            expected: "a valid CIDR or address string",
            actual: "unparseable",
            context: context,
            location: nil
          )
        end
        private_class_method :raise_invalid_addr

        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [String]
        def self.string_value(value, context)
          Base.assert_type(value, expected: StringValue, context: context)
          value.value
        end
        private_class_method :string_value
      end
    end
  end
end

Ruby::Rego::Builtins::Net.register!
