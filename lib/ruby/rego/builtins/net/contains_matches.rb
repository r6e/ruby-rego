# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # net.cidr_contains_matches — the cidr-vs-address containment cross-product. Lives apart
      # from the net.* core so that file stays under RubyCritic's complexity budget. Reopens Net;
      # bare references to shared helpers (parse_cidr, parse_addr, normalize, raise_invalid_addr)
      # resolve via the reopened module's lexical scope.
      module Net
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
      end
    end
  end
end
