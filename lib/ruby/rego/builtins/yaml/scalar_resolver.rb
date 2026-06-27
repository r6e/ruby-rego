# frozen_string_literal: true

require "psych"

module Ruby
  module Rego
    module Builtins
      module Yaml
        # Resolves plain YAML scalars the way gopkg.in/yaml.v2 (v2.4.0) does, and walks
        # a parsed document into JSON-compatible Ruby values — the combination OPA gets
        # from sigs.k8s.io/yaml's YAML→JSON conversion. Notably: timestamps are NOT
        # resolved (they stay strings, matching OPA's JSON round-trip), object keys are
        # stringified, and a non-finite number makes the whole result undefined.
        #
        # Number parsing, !!tag coercion, and the document walk live in sub-files
        # (scalar_resolver/{numbers,tags,document}.rb), required at the bottom, so this
        # file stays under RubyCritic's complexity budget.
        module ScalarResolver
          # Raised when a document cannot be represented as JSON (Inf/NaN), is invalid
          # (undefined alias, bad merge), or breaches a DoS bound. The caller maps it to
          # undefined / false, matching OPA.
          class ResolveError < StandardError; end

          # DoS bounds. OPA relies on Go runtime limits absent here, so an untrusted
          # document exceeding these yields undefined rather than exhausting memory/stack:
          # source byte length, nesting depth (guards a Ruby stack overflow), and total
          # expanded nodes (guards against alias-expansion "billion laughs" bombs).
          MAX_YAML_SOURCE = 1_000_000
          MAX_DEPTH = 1_000
          MAX_NODES = 5_000_000

          # go-yaml resolves an integer via strconv ParseInt (int64) then ParseUint (uint64).
          # ParseUint rejects a sign, so an explicitly +/- signed value is bounded by int64;
          # only an unsigned value may reach uint64 max. A prefixed 0x/0o/0b literal beyond
          # the accepted range can't be reparsed as a float, so it falls back to its string
          # text; an out-of-range !!int (any base) is undefined. A bare integer key in the
          # positive uint64-only band decodes to a Go uint64, which sigs.k8s.io/yaml cannot
          # stringify as a JSON key, so that document is undefined.
          INT64_MIN = -(2**63)
          INT64_MAX = (2**63) - 1
          UINT64_MAX = (2**64) - 1

          # A decimal token of at most this many characters is below 10**308 (< float64 max,
          # ~1.8e308), so it cannot overflow float64 — decimal_overflows_float64? uses this to
          # skip the Float() overflow probe for the common (small-integer) case.
          FLOAT64_FINITE_MAX_DIGITS = 308

          # Plain scalars with a fixed meaning (yaml.v2 resolveMap).
          RESOLVE_MAP = {
            "" => nil, "~" => nil, "null" => nil, "Null" => nil, "NULL" => nil,
            "y" => true, "Y" => true, "yes" => true, "Yes" => true, "YES" => true,
            "true" => true, "True" => true, "TRUE" => true, "on" => true, "On" => true, "ON" => true,
            "n" => false, "N" => false, "no" => false, "No" => false, "NO" => false,
            "false" => false, "False" => false, "FALSE" => false, "off" => false, "Off" => false, "OFF" => false,
            ".nan" => Float::NAN, ".NaN" => Float::NAN, ".NAN" => Float::NAN,
            ".inf" => Float::INFINITY, ".Inf" => Float::INFINITY, ".INF" => Float::INFINITY,
            "+.inf" => Float::INFINITY, "+.Inf" => Float::INFINITY, "+.INF" => Float::INFINITY,
            "-.inf" => -Float::INFINITY, "-.Inf" => -Float::INFINITY, "-.INF" => -Float::INFINITY
          }.freeze

          # Prefix of an explicit core YAML schema tag (e.g. "tag:yaml.org,2002:int").
          TAG_PREFIX = "tag:yaml.org,2002:"

          # First-byte hints that a scalar might be a number (yaml.v2 resolveTable).
          NUMBER_LEADS = "+-.0123456789"
          FLOAT_RE = /\A[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?\z/

          # Resolves a plain scalar string to its Ruby value (or itself, as a string).
          # @return [Object]
          def self.resolve(string)
            return RESOLVE_MAP[string] if RESOLVE_MAP.key?(string)
            return string unless numeric_lead?(string)

            numeric(string) || string
          end

          # True when a plain scalar would resolve to something other than a string
          # (so the emitter must quote it).
          # @return [bool]
          def self.ambiguous?(string)
            resolved = resolve(string)
            !(resolved.is_a?(String) && resolved == string)
          end

          # Parses YAML and returns the first document as JSON-compatible Ruby values.
          # @return [Object]
          def self.load(string)
            raise ResolveError, "yaml too long" if string.bytesize > MAX_YAML_SOURCE

            document = Psych.parse_stream(string).children.first
            # An absent document or one with no root node is an empty document, which
            # decodes to null (matching yaml.v2 / sigs.k8s.io/yaml), not an error.
            return nil if document.nil? || document.root.nil?

            value = build(document.root, {}, 0)
            reject_non_finite(value, [MAX_NODES], 0)
            value
          end

          # Resolves a scalar node's value. An explicit core tag (!!str/!!int/!!float/!!bool/
          # !!null) coerces the value to that type (erroring on a value that can't be coerced,
          # like OPA); otherwise a plain scalar is resolved and a quoted one is a string.
          # @return [Object]
          def self.scalar_value(node)
            tag = node.tag
            return tag_coerce(tag[TAG_PREFIX.length..], node.value) if tag&.start_with?(TAG_PREFIX)

            node.plain ? resolve(node.value) : node.value
          end
          private_class_method :scalar_value
        end
      end
    end
  end
end

require_relative "scalar_resolver/numbers"
require_relative "scalar_resolver/tags"
require_relative "scalar_resolver/document"
