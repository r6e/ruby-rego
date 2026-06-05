# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

# rubocop:disable Metrics/ModuleLength
module Ruby
  module Rego
    module Builtins
      # JSON path projection/redaction helpers (json.filter, json.remove), matching OPA.
      # Both take an object document and an array of paths; each path is a "/"-separated
      # string (JSON-pointer escaped: `~1` is `/`, `~0` is `~`) or an array of literal
      # segments. A numeric string segment indexes into an array. A non-object document or
      # a non-array paths argument yields undefined, as does a path element that is neither
      # a string nor an array. Operations are pure structural rewrites of the parsed value
      # (linear in the document size), so there is no unbounded cost.
      #
      # json.filter keeps only the listed paths (a terminal path keeps the whole subtree; a
      # path that descends past a scalar keeps the scalar; a non-matching child becomes an
      # empty container). json.remove drops the listed paths (removing an array element
      # reindexes; multiple indices under one array are removed against the original
      # positions).
      module JsonPaths
        extend RegistryHelpers

        JSON_PATH_FUNCTIONS = {
          "json.filter" => { arity: 2, handler: :filter },
          "json.remove" => { arity: 2, handler: :remove }
        }.freeze

        # A canonical non-negative array index (no leading zeros), matching how OPA renders
        # an index back to a path segment.
        ARRAY_INDEX = /\A(?:0|[1-9]\d*)\z/

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, JSON_PATH_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param document_value [Ruby::Rego::Value]
        # @param paths_value [Ruby::Rego::Value]
        # @return [Hash]
        def self.filter(document_value, paths_value)
          select(object_document(document_value, "json.filter"), path_trie(paths_value, "json.filter"))
        end

        # @param document_value [Ruby::Rego::Value]
        # @param paths_value [Ruby::Rego::Value]
        # @return [Hash]
        def self.remove(document_value, paths_value)
          prune(object_document(document_value, "json.remove"), path_trie(paths_value, "json.remove"))
        end

        # Selects only the paths recorded in `node` from `value`. A terminal node keeps the
        # value whole; otherwise only matching children are kept (a scalar with a
        # non-terminal node is kept whole — there is nothing to descend into).
        #
        # @param value [Object]
        # @param node [Hash]
        # @return [Object]
        def self.select(value, node)
          return value if node[:terminal]

          case value
          when Hash then select_object(value, node)
          when Array then select_array(value, node)
          else value
          end
        end
        private_class_method :select

        # @param hash [Hash]
        # @param node [Hash]
        # @return [Hash]
        def self.select_object(hash, node)
          result = {} # @type var result: Hash[untyped, untyped]
          node[:children].each do |segment, child|
            result[segment] = select(hash[segment], child) if segment.is_a?(String) && hash.key?(segment)
          end
          result
        end
        private_class_method :select_object

        # @param array [Array]
        # @param node [Hash]
        # @return [Array]
        def self.select_array(array, node)
          kept = [] # @type var kept: Array[untyped]
          array.each_index do |index|
            child = node[:children][index.to_s]
            kept << select(array[index], child) if child
          end
          kept
        end
        private_class_method :select_array

        # Removes the paths recorded in `node` from `value`, mutating it in place (the
        # document is a fresh deep copy from `to_ruby`).
        #
        # @param value [Object]
        # @param node [Hash]
        # @return [Object]
        def self.prune(value, node)
          case value
          when Hash then prune_object(value, node)
          when Array then prune_array(value, node)
          else value
          end
        end
        private_class_method :prune

        # @param hash [Hash]
        # @param node [Hash]
        # @return [Hash]
        def self.prune_object(hash, node)
          node[:children].each do |segment, child|
            next unless segment.is_a?(String) && hash.key?(segment)

            child[:terminal] ? hash.delete(segment) : prune(hash[segment], child)
          end
          hash
        end
        private_class_method :prune_object

        # Recurses into non-terminal children first (positions unchanged), then deletes the
        # terminal indices in descending order so the original positions are removed.
        #
        # @param array [Array]
        # @param node [Hash]
        # @return [Array]
        def self.prune_array(array, node)
          terminal = [] # @type var terminal: Array[Integer]
          node[:children].each do |segment, child|
            index = array_index(segment, array.length)
            next unless index

            child[:terminal] ? terminal << index : prune(array[index], child)
          end
          terminal.sort.reverse_each { |index| array.delete_at(index) }
          array
        end
        private_class_method :prune_array

        # @param segment [Object]
        # @param length [Integer]
        # @return [Integer, nil]
        def self.array_index(segment, length)
          return nil unless segment.is_a?(String) && segment.match?(ARRAY_INDEX)

          index = segment.to_i
          index < length ? index : nil
        end
        private_class_method :array_index

        # @param document_value [Ruby::Rego::Value]
        # @param context [String]
        # @return [Hash]
        def self.object_document(document_value, context)
          Base.assert_type(document_value, expected: ObjectValue, context: context)
          document_value.to_ruby
        end
        private_class_method :object_document

        # Builds a trie of the requested paths; an empty path contributes nothing.
        #
        # @param paths_value [Ruby::Rego::Value]
        # @param context [String]
        # @return [Hash]
        def self.path_trie(paths_value, context)
          Base.assert_type(paths_value, expected: ArrayValue, context: context)
          root = new_node
          paths_value.value.each { |path| insert(root, path_segments(path, context)) }
          root
        end
        private_class_method :path_trie

        # @param path [Ruby::Rego::Value]
        # @param context [String]
        # @return [Array<Object>]
        def self.path_segments(path, context)
          contents = path.value
          case path
          when StringValue then contents.split("/", -1).map { |segment| unescape_pointer(segment) }
          when ArrayValue then contents.map(&:to_ruby)
          else raise_invalid_path(context)
          end
        end
        private_class_method :path_segments

        # @param segment [String]
        # @return [String]
        def self.unescape_pointer(segment)
          segment.gsub("~1", "/").gsub("~0", "~")
        end
        private_class_method :unescape_pointer

        # @param root [Hash]
        # @param segments [Array<Object>]
        # @return [void]
        def self.insert(root, segments)
          return if segments.empty?

          node = segments.reduce(root) { |current, segment| current[:children][segment] ||= new_node }
          node[:terminal] = true
        end
        private_class_method :insert

        # @return [Hash]
        def self.new_node
          { terminal: false, children: {} }
        end
        private_class_method :new_node

        # @param context [String]
        # @return [void]
        def self.raise_invalid_path(context)
          raise Ruby::Rego::BuiltinArgumentError.new(
            "Invalid path",
            expected: "a string or array path",
            actual: "invalid",
            context: context,
            location: nil
          )
        end
        private_class_method :raise_invalid_path
      end
    end
  end
end

Ruby::Rego::Builtins::JsonPaths.register!
# rubocop:enable Metrics/ModuleLength
