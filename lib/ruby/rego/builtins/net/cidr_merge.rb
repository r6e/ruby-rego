# frozen_string_literal: true

# rubocop:disable Metrics/ModuleLength

require "ipaddr"

module Ruby
  module Rego
    module Builtins
      # net.cidr_merge — the Cilium range-merge port. Lives apart from the net.* core so that
      # file stays under RubyCritic's complexity budget. Reopens Net; bare references to shared
      # helpers (string_value, parse_cidr, parse_addr, normalize, raise_invalid_addr) resolve via
      # the reopened module's lexical scope.
      module Net
        IPV4_BITS = 32
        IPV6_BITS = 128
        # Offset of the IPv4-mapped IPv6 block (::ffff:0:0/96); IPv4 ranges live here in the
        # unified merge space so a containing IPv6 range absorbs them as OPA does.
        V4_MAPPED_OFFSET = 0xFFFF << 32

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
          raise_invalid_addr(context) unless Base.byte_safe_encoding?(string)

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
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength
