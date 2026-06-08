# frozen_string_literal: true

# rubocop:disable Metrics/ModuleLength

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

        # cidr_expand has no bound in OPA (it relies on Go's runtime); expanding a CIDR
        # with more than this many addresses yields undefined here. A /12 (IPv4) is ~1M.
        MAX_EXPAND_SIZE = 1_000_000

        IPV4_BITS = 32
        IPV6_BITS = 128
        # Offset of the IPv4-mapped IPv6 block (::ffff:0:0/96); IPv4 ranges live here in the
        # unified merge space so a containing IPv6 range absorbs them as OPA does.
        V4_MAPPED_OFFSET = 0xFFFF << 32

        NET_FUNCTIONS = {
          "net.cidr_contains" => { arity: 2, handler: :cidr_contains },
          "net.cidr_contains_matches" => { arity: 2, handler: :cidr_contains_matches },
          "net.cidr_expand" => { arity: 1, handler: :cidr_expand },
          "net.cidr_intersects" => { arity: 2, handler: :cidr_intersects },
          "net.cidr_is_valid" => { arity: 1, handler: :cidr_is_valid },
          "net.cidr_merge" => { arity: 1, handler: :cidr_merge }
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

        # Expands a CIDR into the set of every address it contains (host bits are masked to
        # the network first, matching OPA). The argument must be a valid CIDR (a prefix is
        # required); a non-string, an invalid CIDR, or a block larger than MAX_EXPAND_SIZE
        # yields undefined.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Set<String>]
        def self.cidr_expand(value)
          cidr = cidr_arg(value, "net.cidr_expand")
          guard_expand_size(cidr, "net.cidr_expand")
          Set.new(cidr.to_range.map { |address| normalize(address).to_s })
        end

        # Merges a list (array or set) of IP addresses and CIDRs into the smallest set of CIDRs
        # covering exactly the same addresses, matching OPA (a port of Cilium's algorithm). A
        # bare IPv4 address takes its classful default mask; a bare IPv6 address is undefined
        # (a prefix is required), as is a non-string element, an unparseable element, or a
        # non-collection operand. IPv4 ranges are merged in their `::ffff:` IPv6-mapped block, so
        # a containing IPv6 range (e.g. `::/0`) absorbs them just as OPA does. A CIDR is masked to
        # its network; a bare address keeps its host form unless it is merged with another.
        #
        # @param value [Ruby::Rego::Value]
        # @return [Set<String>]
        def self.cidr_merge(value)
          Set.new(merge_group(merge_operands(value, "net.cidr_merge")))
        end

        # The parsed range entries for each operand element, or undefined on any invalid input.
        def self.merge_operands(value, context)
          unless value.is_a?(ArrayValue) || value.is_a?(SetValue)
            Base.raise_argument_error("operand must be an array or set",
                                      expected: "array or set", actual: value.type_name, context: context)
          end
          value.value.to_a.map { |element| merge_entry(element, context) }
        end
        private_class_method :merge_operands

        # Parses one element into { first:, last:, original: }. first/last are integers in a
        # unified space where IPv4 ranges are mapped to their `::ffff:` block — so a containing
        # IPv6 range (e.g. `::/0`) absorbs IPv4 entries exactly as OPA does. `original` is the
        # IPNet string OPA keeps for a network that is never merged.
        def self.merge_entry(element, context)
          string = string_value(element, context)
          # Guard the encoding before `include?` so a non-ASCII-compatible string (e.g. UTF-16LE)
          # yields undefined rather than raising Encoding::CompatibilityError, matching the other
          # net builtins (whose parse_addr checks encoding first).
          raise_invalid_addr(context) unless string.encoding.ascii_compatible? && string.valid_encoding?

          string.include?("/") ? cidr_entry(string, context) : address_entry(string, context)
        end
        private_class_method :merge_entry

        # :reek:TooManyStatements
        def self.cidr_entry(string, context)
          addr = normalize(parse_cidr(string) || raise_invalid_addr(context))
          range = addr.to_range
          bits = addr.ipv4? ? IPV4_BITS : IPV6_BITS
          offset = bits == IPV4_BITS ? V4_MAPPED_OFFSET : 0
          network = range.first.to_i
          { first: network + offset, last: range.last.to_i + offset,
            original: cidr_string(network, addr.prefix, bits) }
        end
        private_class_method :cidr_entry

        # A bare IPv4 address as a classful-masked range, keeping its host form as the original.
        def self.address_entry(string, context)
          classful_entry(v4_address(string, context))
        end
        private_class_method :address_entry

        # A bare IPv4 host as a classful range mapped into the unified space's `::ffff:` block.
        def self.classful_entry(addr)
          ip = addr.to_i
          prefix = classful_prefix(ip)
          host_bits = IPV4_BITS - prefix
          first = (ip >> host_bits) << host_bits
          { first: first + V4_MAPPED_OFFSET, last: (first | ((1 << host_bits) - 1)) + V4_MAPPED_OFFSET,
            original: "#{addr}/#{prefix}" }
        end
        private_class_method :classful_entry

        # Parses a bare address that must be IPv4 (a bare IPv6 needs a prefix), or undefined.
        def self.v4_address(string, context)
          addr = parse_addr(string)
          native = normalize(addr) if addr
          native&.ipv4? ? native : raise_invalid_addr(context)
        end
        private_class_method :v4_address

        # Go's net.IP.DefaultMask: classful by leading octet (A=/8, B=/16, C and above=/24).
        def self.classful_prefix(ip)
          leading = ip >> 24
          return 8 if leading < 0x80
          return 16 if leading < 0xC0

          24
        end
        private_class_method :classful_prefix

        # :reek:TooManyStatements
        # Unions the entries' ranges and emits CIDR strings. An untouched range keeps OPA's
        # original network string; a merged range is decomposed into canonical CIDRs.
        def self.merge_group(entries)
          sorted = entries.sort_by { |entry| [entry[:first], entry[:last]] }
          merged = sorted.each_with_object([]) { |entry, acc| fold_range(acc, entry) }
          merged.flat_map { |range| range[:original] || range_to_cidrs(range[:first], range[:last]) }
        end
        private_class_method :merge_group

        # Adds `entry` to the accumulated ranges, unioning it into the last range when it
        # overlaps or is adjacent (which clears that range's original so it is re-decomposed).
        def self.fold_range(merged, entry)
          previous = merged.last
          last = previous && previous[:last]
          if last && entry[:first] <= last + 1
            merged[-1] = { first: previous[:first], last: [last, entry[:last]].max, original: nil }
          else
            merged << entry
          end
        end
        private_class_method :fold_range

        # Decomposes a merged [first, last] range (unified v4-mapped space) into the minimal CIDR
        # set. Each block is rendered IPv4 when it lies in the `::ffff:` block, else IPv6 — OPA
        # picks the family per output CIDR (alignment keeps a v4-mapped block within that block).
        def self.range_to_cidrs(first, last)
          cidrs = [] # @type var cidrs: Array[String]
          while first <= last
            block = [alignment_bits(first, IPV6_BITS), (last - first + 1).bit_length - 1].min
            cidrs << block_cidr(first, IPV6_BITS - block)
            first += 1 << block
          end
          cidrs
        end
        private_class_method :range_to_cidrs

        # Formats a single aligned block (given its 128-bit prefix) as IPv4 or IPv6.
        def self.block_cidr(low, prefix)
          return cidr_string(low, prefix, IPV6_BITS) unless v4_mapped?(low)

          cidr_string(low - V4_MAPPED_OFFSET, prefix - (IPV6_BITS - IPV4_BITS), IPV4_BITS)
        end
        private_class_method :block_cidr

        def self.v4_mapped?(int)
          int.between?(V4_MAPPED_OFFSET, V4_MAPPED_OFFSET + 0xFFFF_FFFF)
        end
        private_class_method :v4_mapped?

        # The largest power-of-two block (in bits) that can start at `low` given its alignment.
        def self.alignment_bits(low, bits)
          low.zero? ? bits : (low & -low).bit_length - 1
        end
        private_class_method :alignment_bits

        def self.cidr_string(network, prefix, bits)
          "#{format_address(network, bits)}/#{prefix}"
        end
        private_class_method :cidr_string

        # Formats an integer address as a string. IPv6 uses an RFC 5952 renderer matching Go's
        # net.IP.String() — notably without the deprecated IPv4-compatible "::a.b.c.d" form that
        # IPAddr emits for low addresses.
        # :reek:ControlParameter
        def self.format_address(int, bits)
          return [24, 16, 8, 0].map { |shift| (int >> shift) & 0xff }.join(".") if bits == IPV4_BITS

          format_ipv6(int)
        end
        private_class_method :format_address

        # :reek:UncommunicativeMethodName
        def self.format_ipv6(int)
          hex = Array.new(8) { |group| ((int >> (16 * (7 - group))) & 0xffff).to_s(16) }
          start, length = longest_zero_run(hex)
          return hex.join(":") if length < 2

          "#{hex.first(start).join(":")}::#{hex.drop(start + length).join(":")}"
        end
        private_class_method :format_ipv6

        # The start index and length of the leftmost longest run of "0" groups.
        # :reek:TooManyStatements
        def self.longest_zero_run(hex)
          best_start = best_length = index = 0
          while index < hex.length
            run = zero_run_length(hex, index)
            if run > best_length
              best_start = index
              best_length = run
            end
            index += [run, 1].max
          end
          [best_start, best_length]
        end
        private_class_method :longest_zero_run

        # The number of consecutive "0" groups starting at `start` (0 if `start` is non-zero).
        def self.zero_run_length(hex, start)
          length = 0
          length += 1 while hex[start + length] == "0"
          length
        end
        private_class_method :zero_run_length

        # The set of `[cidr_key, addr_key]` pairs for which a CIDR in the first collection
        # contains an address/CIDR in the second. Each operand may be an array (key is the
        # index), object (key is the key), set or scalar (key is the element itself). A
        # first-collection element must be a valid CIDR, a second-collection element a valid
        # IP or CIDR; any non-string or unparseable element yields undefined.
        #
        # @param cidrs [Ruby::Rego::Value]
        # @param addrs [Ruby::Rego::Value]
        # @return [Set<Array>]
        def self.cidr_contains_matches(cidrs, addrs)
          context = "net.cidr_contains_matches"
          networks = entries(cidrs)
          return Set.new if networks.empty?

          # OPA structurally checks every cidr-side element (it must be a string or a
          # non-empty array) even with no addresses, but only value-parses — and touches the
          # address side at all — once the address side is non-empty.
          validate_structure(networks, context)
          addresses = entries(addrs)
          return Set.new if addresses.empty?

          containment_pairs(
            networks.map { |key, element| [key, normalize(cidr_from(element, context))] },
            addresses.map { |key, element| [key, normalize(addr_from(element, context))] }
          )
        end

        # Structurally checks every cidr-side element (see #structural_check).
        # @return [void]
        def self.validate_structure(collection, context)
          collection.each { |entry| structural_check(entry[1], context) }
        end
        private_class_method :validate_structure

        # OPA's structural element check (`getCIDRMatchTerm`): a string or a non-empty array
        # (its contents are only validated later, when value-parsed). Anything else is
        # undefined.
        # @return [void]
        def self.structural_check(element, context)
          return if element.is_a?(::String)
          return if element.is_a?(::Array) && !element.empty?

          raise_invalid_addr(context)
        end
        private_class_method :structural_check

        # @return [Set<Array>]
        def self.containment_pairs(networks, addresses)
          networks.product(addresses).each_with_object(Set.new) do |(network, address), pairs|
            cidr_key, cidr = network
            addr_key, addr = address
            pairs << [cidr_key, addr_key] if cidr.include?(addr)
          end
        end
        private_class_method :containment_pairs

        # Yields `[key, element]` for each member of a collection operand: array → index,
        # object → key, set → the element, and a bare scalar → itself (matching OPA's
        # collection-or-scalar handling).
        #
        # @param value [Ruby::Rego::Value]
        # @return [Array<Array>]
        def self.entries(value)
          ruby = value.to_ruby
          case ruby
          when ::Array then ruby.each_with_index.map { |element, index| [index, element] }
          when ::Hash then ruby.to_a
          when ::Set then ruby.map { |element| [element, element] }
          else [[ruby, ruby]]
          end
        end
        private_class_method :entries

        # @return [IPAddr]
        def self.cidr_from(element, context)
          parse_cidr(match_string(element, context)) || raise_invalid_addr(context)
        end
        private_class_method :cidr_from

        # @return [IPAddr]
        def self.addr_from(element, context)
          parse_addr(match_string(element, context)) || raise_invalid_addr(context)
        end
        private_class_method :addr_from

        # An operand element is the address string itself, or a non-empty array whose first
        # element is the address — OPA accepts `[cidr, metadata]` tuples, keying the match by
        # the tuple's position. A non-string (or empty-array) element yields undefined.
        #
        # @return [String]
        def self.match_string(element, context)
          target = element.is_a?(::Array) ? element[0] : element
          target.is_a?(::String) ? target : raise_invalid_addr(context)
        end
        private_class_method :match_string

        # Rejects (→ undefined) a CIDR whose address count exceeds MAX_EXPAND_SIZE.
        # @return [void]
        def self.guard_expand_size(cidr, context)
          size = 1 << ((cidr.ipv4? ? 32 : 128) - cidr.prefix)
          return if size <= MAX_EXPAND_SIZE

          Base.raise_argument_error(
            "#{context} size #{size} exceeds maximum #{MAX_EXPAND_SIZE}",
            expected: "size <= #{MAX_EXPAND_SIZE}", actual: size.to_s, context: context
          )
        end
        private_class_method :guard_expand_size

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
          Base.raise_argument_error(
            "Invalid CIDR or address",
            expected: "a valid CIDR or address string", actual: "unparseable", context: context
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
# rubocop:enable Metrics/ModuleLength

Ruby::Rego::Builtins::Net.register!
