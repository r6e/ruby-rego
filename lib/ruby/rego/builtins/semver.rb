# frozen_string_literal: true

require_relative "base"
require_relative "registry"
require_relative "registry_helpers"

# rubocop:disable Naming/PredicatePrefix
module Ruby
  module Rego
    module Builtins
      # Built-in Semantic Versioning helpers (semver.is_valid, semver.compare), matching
      # OPA (which vendors coreos/go-semver). A version is MAJOR.MINOR.PATCH[-PRERELEASE]
      # [+BUILD]; OPA's parser is lenient — it accepts a leading lowercase "v" and leading
      # zeros in numeric components — but each numeric component must fit in a signed 64-bit
      # integer. is_valid is total over runtime values (a non-string yields false); compare
      # yields undefined for a non-string or invalid version. Build metadata is ignored when
      # comparing; precedence follows SemVer §11.
      #
      # Intentional divergence: OPA's semver.compare infinite-loops while comparing two
      # numeric prerelease identifiers in a few cases — most visibly when they are equal in
      # value but differ textually via leading zeros (e.g. "1.0.0-01" vs "1.0.0-1"), and
      # also when one straddles the 64-bit boundary — an upstream coreos/go-semver bug. This
      # implementation compares prerelease identifiers numerically and terminates on every
      # input, returning the correct SemVer result instead of hanging.
      module Semver
        extend RegistryHelpers

        SEMVER_FUNCTIONS = {
          "semver.is_valid" => { arity: 1, handler: :is_valid },
          "semver.compare" => { arity: 2, handler: :compare }
        }.freeze

        # Largest value a numeric component (or numeric prerelease identifier) may take;
        # a larger value is invalid for a component, and is treated as a string identifier
        # in a prerelease (matching coreos/go-semver's int64 parse).
        MAX_COMPONENT = (2**63) - 1

        # A dot-separated run of [0-9A-Za-z-] identifiers (prerelease or build metadata).
        IDENTIFIERS = /\A[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*\z/

        # A numeric component / identifier: ASCII digits only (leading zeros allowed).
        NUMERIC = /\A\d+\z/

        # A parsed version: numeric major/minor/patch and a list of prerelease identifiers
        # (empty for a release). Build metadata is dropped — it does not affect comparison.
        Version = Struct.new(:major, :minor, :patch, :prerelease)

        # @return [Ruby::Rego::Builtins::BuiltinRegistry]
        def self.register!
          registry = BuiltinRegistry.instance
          register_configured_functions(registry, SEMVER_FUNCTIONS)
          registry
        end

        private_class_method :register_configured_functions, :register_configured_function

        # @param value [Ruby::Rego::Value]
        # @return [Ruby::Rego::BooleanValue]
        # :reek:NilCheck
        def self.is_valid(value)
          return BooleanValue.new(false) unless value.is_a?(StringValue)

          BooleanValue.new(!parse(value.value).nil?)
        end

        # @param a_value [Ruby::Rego::Value]
        # @param b_value [Ruby::Rego::Value]
        # @return [Ruby::Rego::NumberValue]
        def self.compare(a_value, b_value)
          first = version_arg(a_value, "semver.compare")
          second = version_arg(b_value, "semver.compare")
          NumberValue.new(compare_versions(first, second))
        end

        # Parses `value` to a Version, or raises (→ undefined) for a non-string or invalid
        # version.
        #
        # @param value [Ruby::Rego::Value]
        # @param context [String]
        # @return [Version]
        def self.version_arg(value, context)
          parse(string_value(value, context)) || raise_invalid_version(context)
        end
        private_class_method :version_arg

        # Parses a version string to a Version, or nil if it is not a valid SemVer string.
        # Metadata is split off first (after `+`), then prerelease (after `-`), matching
        # coreos/go-semver — so a trailing `-`/`+` (empty prerelease/build) is valid.
        #
        # @param string [String]
        # @return [Version, nil]
        def self.parse(string)
          return nil unless string.encoding.ascii_compatible? && string.valid_encoding?

          rest, _, metadata = string.delete_prefix("v").partition("+")
          core, _, prerelease = rest.partition("-")
          return nil unless valid_identifiers?(metadata) && valid_identifiers?(prerelease)

          build_version(core, prerelease)
        end
        private_class_method :parse

        # @param core [String] the major.minor.patch part
        # @param prerelease [String]
        # @return [Version, nil]
        def self.build_version(core, prerelease)
          parts = core.split(".", 3)
          return nil unless parts.length == 3

          major, minor, patch = parts.map { |part| bounded_integer(part) }
          return nil unless major && minor && patch

          Version.new(major, minor, patch, prerelease.split("."))
        end
        private_class_method :build_version

        # @param string [String]
        # @return [Boolean]
        def self.valid_identifiers?(string)
          string.empty? || string.match?(IDENTIFIERS)
        end
        private_class_method :valid_identifiers?

        # Parses a non-negative integer string bounded to a signed 64-bit value, returning
        # nil when it is non-numeric or out of range. Used both for numeric core components
        # (where out-of-range is invalid) and for classifying prerelease identifiers (where
        # an out-of-range numeric string is treated as a string identifier).
        #
        # @param string [String]
        # @return [Integer, nil]
        def self.bounded_integer(string)
          return nil unless string.match?(NUMERIC)

          number = string.to_i
          number <= MAX_COMPONENT ? number : nil
        end
        private_class_method :bounded_integer

        # @param first [Version]
        # @param second [Version]
        # @return [Integer] -1, 0, or 1
        def self.compare_versions(first, second)
          [first.major <=> second.major, first.minor <=> second.minor,
           first.patch <=> second.patch].each do |order|
            return order unless order.zero?
          end
          compare_prerelease(first.prerelease, second.prerelease)
        end
        private_class_method :compare_versions

        # Compares prerelease identifier lists per SemVer §11. An empty list (a release)
        # ranks above a non-empty one; otherwise compare identifier by identifier, and a
        # larger set outranks a smaller one when all shared identifiers are equal.
        #
        # @param first [Array<String>]
        # @param second [Array<String>]
        # @return [Integer]
        # rubocop:disable Metrics/MethodLength
        def self.compare_prerelease(first, second)
          first_empty = first.empty?
          second_empty = second.empty?
          return 0 if first_empty && second_empty
          return 1 if first_empty
          return -1 if second_empty

          first_length = first.length
          second_length = second.length
          [first_length, second_length].min.times do |index|
            order = compare_identifier(first[index], second[index])
            return order unless order.zero?
          end
          first_length <=> second_length
        end
        # rubocop:enable Metrics/MethodLength
        private_class_method :compare_prerelease

        # Compares two prerelease identifiers: numeric identifiers compare by value and rank
        # below alphanumeric ones, which compare lexically (ASCII).
        #
        # @param first [String]
        # @param second [String]
        # @return [Integer]
        def self.compare_identifier(first, second)
          first_num = bounded_integer(first)
          second_num = bounded_integer(second)
          return first_num <=> second_num if first_num && second_num
          return -1 if first_num
          return 1 if second_num

          first <=> second
        end
        private_class_method :compare_identifier

        # @param context [String]
        # @return [void]
        def self.raise_invalid_version(context)
          Base.raise_argument_error(
            "Invalid semantic version", expected: "a valid SemVer string", actual: "unparseable", context: context
          )
        end
        private_class_method :raise_invalid_version

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

Ruby::Rego::Builtins::Semver.register!
# rubocop:enable Naming/PredicatePrefix
