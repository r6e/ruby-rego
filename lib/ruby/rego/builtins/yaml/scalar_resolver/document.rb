# frozen_string_literal: true

# rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity

module Ruby
  module Rego
    module Builtins
      module Yaml
        # Walks a parsed Psych document into JSON-compatible Ruby values: node dispatch,
        # anchors/aliases, `<<` merge keys, JSON object-key stringification, and the
        # non-finite/DoS rejection pass. Lives apart from the resolution core so the main
        # file stays under RubyCritic's complexity budget; constants and self-dispatched
        # helpers (scalar_value, MAX_DEPTH, ...) resolve via lexical scope / the module.
        module ScalarResolver
          # @return [Object]
          # :reek:TooManyStatements
          def self.build(node, anchors, depth)
            raise ResolveError, "yaml nested too deep" if depth > MAX_DEPTH

            case node
            when Psych::Nodes::Scalar then anchored(node, anchors) { scalar_value(node) }
            when Psych::Nodes::Sequence
              anchored(node, anchors) { node.children.map { |child| build(child, anchors, depth + 1) } }
            when Psych::Nodes::Mapping then build_mapping(node, anchors, depth)
            when Psych::Nodes::Alias then anchors.fetch(node.anchor) { raise ResolveError, "undefined alias #{node.anchor}" }
            else raise ResolveError, "unsupported node #{node.class}"
            end
          end
          private_class_method :build

          # Registers a built value under its anchor (if any) so later aliases resolve.
          def self.anchored(node, anchors)
            value = yield
            anchor = node.anchor
            anchors[anchor] = value if anchor && !anchor.empty?
            value
          end
          private_class_method :anchored

          # :reek:TooManyStatements
          def self.build_mapping(node, anchors, depth)
            result = {} # @type var result: Hash[String, untyped]
            anchored(node, anchors) { result }
            node.children.each_slice(2) do |key_node, value_node|
              key = build(key_node, anchors, depth + 1)
              built = build(value_node, anchors, depth + 1)
              next merge_into(result, built) if merge_key?(key, key_node)

              result[json_key(key, key_node)] = built
            end
            result
          end
          private_class_method :build_mapping

          # A `<<` merge key applies only when written as a plain scalar (a quoted
          # "<<" is an ordinary string key, matching yaml.v2's isMerge).
          def self.merge_key?(key, key_node)
            key == "<<" && key_node.is_a?(Psych::Nodes::Scalar) && key_node.plain
          end
          private_class_method :merge_key?

          # YAML merge key (`<<`): fill in entries not already present. A non-mapping
          # merge source is invalid (yaml.v2 errors), so it yields undefined.
          def self.merge_into(result, source)
            sources = source.is_a?(Array) ? source : [source]
            sources.each do |entry|
              raise ResolveError, "merge source is not a mapping" unless entry.is_a?(Hash)

              entry.each { |key, value| result[key] = value unless result.key?(key) }
            end
          end
          private_class_method :merge_into

          # JSON object keys are strings: resolve the key and stringify it (so 0x1F => "31",
          # 1.0 => "1", true => "true"). A non-finite float key normalizes to OPA's
          # canonical form. NOTE: a finite non-integer float key (e.g. 1.123456789) is
          # formatted with Ruby float64 shortest, whereas OPA uses Go float32 ('g', -1, 32),
          # so very-high-precision float map keys can differ — a rare, documented edge. The
          # same float32 cast also overflows a finite float64 key above ~3.4e38 (e.g. 1e308) to
          # ±Inf, which OPA renders as a ".inf"/"-.inf" key where the gem keeps the float64 text;
          # both stay defined (same divergence family, deferred to the number sweep).
          # @return [String]
          def self.json_key(key, key_node)
            return canonical_float(key) if key.is_a?(Float) && !key.finite?

            case key
            when String then key
            when true then "true"
            when false then "false"
            when Integer then integer_key(key, key_node)
            when Float then Emitter.float_string(key)
            # A null or composite (array/object) key cannot be a JSON object key, so OPA's
            # round-trip rejects it; yield undefined to match.
            else raise ResolveError, "invalid object key #{key.class}"
            end
          end
          private_class_method :json_key

          # Only an UNSIGNED INTEGER-resolved key in the positive uint64-only band decodes to a
          # Go uint64, which sigs.k8s.io/yaml has no JSON-key case for, so OPA's round-trip
          # rejects the whole document (undefined). Everything else in/around that band is a
          # defined string key, rendered here as the key's exact parsed value (a deferred lossy-
          # float text divergence vs OPA): a `+` SIGNED value (ParseUint rejects the sign →
          # float64), a value beyond uint64 max, OR a FLOAT-resolved key (plain float syntax or
          # a !!float tag) that rounds into the band — all are float64 keys that stringify fine.
          # @return [String]
          def self.integer_key(key, key_node)
            raise ResolveError, "invalid object key (uint64 band)" if uint64_object_key?(key, key_node)

            key.to_s
          end
          private_class_method :integer_key

          # @return [bool]
          def self.uint64_object_key?(key, key_node)
            return false unless uint64_band?(key)
            # A non-scalar (alias) key loses its provenance (sign, float-ness, tag); assume the
            # common unsigned-integer anchor (undefined), accepting the documented alias-key
            # deferral for a signed-integer OR float-rounds-into-band value reached via an alias.
            return true unless key_node.is_a?(Psych::Nodes::Scalar)

            !float_tagged?(key_node) && integer_origin?(key_node)
          end
          private_class_method :uint64_object_key?

          # Whether a scalar carries an explicit !!float tag (a float64 value, never a uint64).
          # @return [bool]
          def self.float_tagged?(node)
            node.tag == "#{TAG_PREFIX}float"
          end
          private_class_method :float_tagged?

          # Whether a scalar resolves as an UNSIGNED integer (a Go uint64 in this band), as
          # opposed to float syntax (e.g. 9.2e18) that rounds to an integer value. Underscores
          # are stripped to match resolution.
          # @return [bool]
          def self.integer_origin?(node)
            text = node.value.delete("_")
            !explicitly_signed?(text) && !parse_integer(text).nil?
          end
          private_class_method :integer_origin?

          # @return [String]
          def self.canonical_float(float)
            return ".nan" if float.nan?

            float.positive? ? ".inf" : "-.inf"
          end
          private_class_method :canonical_float

          # JSON cannot represent Inf/NaN (=> undefined). The budget caps total expansion
          # (alias bombs), and the depth cap stops cyclic anchors (e.g. `a: &a {b: *a}`)
          # before they overflow the stack — both surface as undefined.
          def self.reject_non_finite(value, budget, depth)
            budget[0] -= 1
            raise ResolveError, "yaml too large" if budget[0].negative?
            raise ResolveError, "yaml nested too deep" if depth > MAX_DEPTH

            case value
            when Float then raise ResolveError, "non-finite number" unless value.finite?
            when Array then value.each { |item| reject_non_finite(item, budget, depth + 1) }
            when Hash then value.each_value { |item| reject_non_finite(item, budget, depth + 1) }
            end
          end
          private_class_method :reject_non_finite
        end
      end
    end
  end
end
# rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity
