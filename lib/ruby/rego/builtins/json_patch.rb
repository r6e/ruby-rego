# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

# rubocop:disable Metrics/ModuleLength
module Ruby
  module Rego
    module Builtins
      # JSON Patch (json.patch), matching OPA — applies an RFC 6902 operation list to a
      # document. Each operation is an object with `op` (add/remove/replace/move/copy/test) and
      # a `path` (an RFC 6901 JSON pointer string, with `~1` for `/` and `~0` for `~`, or an
      # array of segments — a string for an object key, a string or integer for an array index);
      # `add`/`replace`/`test` need a `value`, `move`/`copy` need a `from`. In a string path a
      # leading run of slashes is stripped, the empty string `""` addresses the whole document,
      # and a path that is only slashes (`/`, `//`) addresses the empty-string key `""`.
      # Operations apply in order. Any failure — a non-array operand, an operation that is not an
      # object, a missing/invalid field, a path into a non-existent or scalar location, an
      # out-of-range array index, or a failed `test` — yields undefined.
      module JsonPatch
        extend RegistryHelpers

        # A canonical non-negative array index (no leading zeros), matching how OPA renders and
        # accepts an index (its EditTree rejects leading zeros).
        ARRAY_INDEX = /\A(?:0|[1-9]\d*)\z/

        JSON_PATCH_FUNCTIONS = {
          "json.patch" => { arity: 2, handler: :patch }
        }.freeze

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, JSON_PATCH_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # Applies the operation list to the document, or undefined on any failure.
        #
        # @param document_value [Ruby::Rego::Value]
        # @param operations_value [Ruby::Rego::Value]
        # @return [Object]
        def self.patch(document_value, operations_value)
          Base.assert_type(operations_value, expected: ArrayValue, context: "json.patch")
          document = document_value.to_ruby
          operations_value.to_ruby.reduce(document) { |doc, operation| apply(doc, operation) }
        end

        # @return [Object]
        def self.apply(document, operation)
          raise_patch_error unless operation.is_a?(Hash)

          path = parse_pointer(fetch_field(operation, "path"))
          dispatch(document, path, operation)
        end
        private_class_method :apply

        # :reek:TooManyStatements
        # :reek:DuplicateMethodCall
        def self.dispatch(document, path, operation)
          case fetch_field(operation, "op")
          when "add" then add_at(document, path, value_of(operation))
          when "remove" then remove_at(document, path)
          when "replace" then replace_at(document, path, value_of(operation))
          when "move" then move(document, path, operation)
          when "copy" then copy(document, path, operation)
          when "test" then test_at(document, path, value_of(operation))
          else raise_patch_error
          end
        end
        private_class_method :dispatch

        def self.move(document, path, operation)
          from = parse_pointer(fetch_field(operation, "from"))
          chunk = fetch_at(document, from)
          remove_at(document, from)
          add_at(document, path, chunk)
        end
        private_class_method :move

        def self.copy(document, path, operation)
          from = parse_pointer(fetch_field(operation, "from"))
          add_at(document, path, deep_dup(fetch_at(document, from)))
        end
        private_class_method :copy

        # Inserts `value` at `path`; an empty path replaces the whole document.
        def self.add_at(document, path, value)
          return value if path.empty?

          insert(fetch_at(document, parent_path(path)), path[-1], value)
          document
        end
        private_class_method :add_at

        def self.replace_at(document, path, value)
          return value if path.empty?

          remove_at(document, path)
          add_at(document, path, value)
        end
        private_class_method :replace_at

        def self.remove_at(document, path)
          raise_patch_error if path.empty?

          delete(fetch_at(document, parent_path(path)), path[-1])
          document
        end
        private_class_method :remove_at

        # :reek:ControlParameter
        def self.test_at(document, path, value)
          raise_patch_error unless fetch_at(document, path) == value

          document
        end
        private_class_method :test_at

        # Walks to the value at `path`; every segment must resolve (a missing key/index or a
        # scalar mid-path is undefined).
        def self.fetch_at(node, segments)
          segments.reduce(node) { |current, segment| step(current, segment) }
        end
        private_class_method :fetch_at

        def self.step(node, segment)
          case node
          when Hash then node.fetch(string_key(segment)) { raise_patch_error }
          when Array then array_member(node, segment)
          else raise_patch_error
          end
        end
        private_class_method :step

        def self.array_member(array, segment)
          index = array_index(segment, array.length, append: false)
          raise_patch_error unless index

          array[index]
        end
        private_class_method :array_member

        def self.insert(parent, segment, value)
          case parent
          when Hash then parent[string_key(segment)] = value
          when Array then array_insert(parent, segment, value)
          else raise_patch_error
          end
        end
        private_class_method :insert

        def self.array_insert(array, segment, value)
          index = array_index(segment, array.length, append: true)
          raise_patch_error unless index

          array.insert(index, value)
        end
        private_class_method :array_insert

        def self.delete(parent, segment)
          case parent
          when Hash then delete_key(parent, string_key(segment))
          when Array then array_delete(parent, segment)
          else raise_patch_error
          end
        end
        private_class_method :delete

        def self.delete_key(hash, key)
          hash.key?(key) ? hash.delete(key) : raise_patch_error
        end
        private_class_method :delete_key

        def self.array_delete(array, segment)
          index = array_index(segment, array.length, append: false)
          raise_patch_error unless index

          array.delete_at(index)
        end
        private_class_method :array_delete

        # An object-key segment must be a string. String JSON-pointer paths always satisfy this;
        # an array-form path with a non-string key segment (which OPA coerces) is not supported.
        def self.string_key(segment)
          segment.is_a?(String) ? segment : raise_patch_error
        end
        private_class_method :string_key

        # The array index a segment addresses (an Integer, a canonical numeric string, or "-" for
        # the append slot when allowed), bounded to the array, or nil if it does not address one.
        # @return [Integer, nil]
        # :reek:ControlParameter
        def self.array_index(segment, length, append:)
          return length if append && segment == "-"

          index = numeric_index(segment)
          index if index&.between?(0, append ? length : length - 1)
        end
        private_class_method :array_index

        # @return [Integer, nil]
        def self.numeric_index(segment)
          return segment if segment.is_a?(Integer)

          segment.to_i if segment.is_a?(String) && segment.match?(ARRAY_INDEX)
        end
        private_class_method :numeric_index

        # @return [Array]
        def self.parse_pointer(path)
          case path
          when String then string_pointer(path)
          when Array then path
          else raise_patch_error
          end
        end
        private_class_method :parse_pointer

        # RFC 6901: "" is the whole document, but a path of only slashes ("/", "//") is the
        # empty-string key — OPA strips leading slashes yet still yields one empty segment there.
        def self.string_pointer(path)
          return [] if path.empty?

          stripped = path.sub(%r{\A/+}, "")
          return [""] if stripped.empty?

          stripped.split("/", -1).map { |segment| unescape(segment) }
        end
        private_class_method :string_pointer

        # The path to the parent container (all but the last segment).
        def self.parent_path(path)
          path[0...-1] || []
        end
        private_class_method :parent_path

        # RFC 6901 unescaping: ~1 -> / then ~0 -> ~ (order matters).
        def self.unescape(segment)
          segment.gsub("~1", "/").gsub("~0", "~")
        end
        private_class_method :unescape

        def self.fetch_field(operation, key)
          operation.key?(key) ? operation[key] : raise_patch_error
        end
        private_class_method :fetch_field

        def self.value_of(operation)
          fetch_field(operation, "value")
        end
        private_class_method :value_of

        # :reek:DuplicateMethodCall
        def self.deep_dup(value)
          case value
          when Hash then value.transform_values { |element| deep_dup(element) }
          when Array then value.map { |element| deep_dup(element) }
          else value
          end
        end
        private_class_method :deep_dup

        def self.raise_patch_error
          Base.raise_argument_error("invalid JSON patch operation",
                                    expected: "a valid RFC 6902 patch", actual: "invalid", context: "json.patch")
        end
        private_class_method :raise_patch_error
      end
    end
  end
end
# rubocop:enable Metrics/ModuleLength

Ruby::Rego::Builtins::JsonPatch.register!
