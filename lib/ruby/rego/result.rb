# frozen_string_literal: true

require "json"
require_relative "error_payload"
require_relative "value"

module Ruby
  module Rego
    # Represents the outcome of evaluating a policy or expression.
    class Result
      # Evaluated value.
      #
      # @return [Value]
      attr_reader :value

      # Variable bindings captured during evaluation.
      #
      # @return [Hash{String => Value}]
      attr_reader :bindings

      # True when evaluation succeeded and produced a value.
      #
      # @return [Boolean]
      attr_reader :success

      # Errors collected during evaluation.
      #
      # @return [Array<Object>]
      attr_reader :errors

      # Create a result wrapper.
      #
      # @param value [Object] evaluation value
      # @param success [Boolean] success flag
      # @param bindings [Hash{String, Symbol => Object}] variable bindings
      # @param errors [Array<Object>] collected errors
      def initialize(value:, success:, bindings: {}, errors: [])
        @value = Value.from_ruby(value)
        @bindings = {} # @type var @bindings: Hash[String, Value]
        add_bindings(bindings)
        @success = success
        @errors = errors.dup
      end

      # Convenience success predicate.
      #
      # @return [Boolean]
      def success?
        success
      end

      # True when the value is undefined.
      #
      # @return [Boolean]
      def undefined?
        value.is_a?(UndefinedValue)
      end

      # Convert the result to a serializable hash.
      #
      # @return [Hash{Symbol => Object}]
      def to_h
        {
          value: value.to_ruby,
          bindings: bindings.transform_values(&:to_ruby),
          success: success,
          errors: errors.map { |error| ErrorPayload.from(error) }
        }
      end

      # Serialize the result as JSON.
      #
      # @param _args [Array<Object>]
      # @return [String]
      def to_json(*args)
        options = args.first
        sanitized = sanitize_json(to_h)
        return JSON.generate(sanitized) unless options.is_a?(Hash)

        JSON.generate(sanitized, options)
      end

      private

      # Sanitize a to_h structure for JSON output the way Go's encoding/json does: a string with
      # invalid-UTF-8 or ASCII-8BIT (binary) bytes — e.g. a value built from base64.decode, including as
      # an object KEY — has each invalid byte sequence replaced by U+FFFD, matching OPA byte-for-byte,
      # rather than raising JSON::GeneratorError (which would escape as an uncaught error). Rego values keep
      # their original bytes internally (this only re-maps at the JSON boundary, like Go); valid UTF-8 /
      # ASCII strings are returned unchanged.
      # :reek:UtilityFunction :reek:TooManyStatements
      def sanitize_json(object)
        case object
        when ::String then scrub_invalid_bytes(object)
        when ::Float then sanitize_float(object)
        when ::Hash then object.to_h { |key, value| [sanitize_json(key), sanitize_json(value)] }
        when ::Array, ::Set then object.map { |element| sanitize_json(element) }
        else object
        end
      end

      # A non-finite Float (Infinity / NaN) is not valid JSON and would raise JSON::GeneratorError. Rego
      # literals and arithmetic can no longer produce one (the arbitrary-precision Number model), but a
      # number beyond Float range read from `input`/`data` JSON (e.g. `{"n": 1e999}` -> Ruby parses
      # Float::INFINITY) still can. Emit null so serialization stays total instead of aborting; preserving
      # the value needs arbitrary-precision input parsing, tracked for the json.unmarshal / input sweep.
      # OPA, which parses input as bignums, never produces a non-finite number.
      # :reek:UtilityFunction
      def sanitize_float(float)
        float.finite? ? float : nil
      end

      # Replace each invalid byte sequence with one U+FFFD PER BYTE, matching Go's encoding/json (which
      # advances by utf8.DecodeRune's reported size — one byte per ill-formed position). Ruby's bare
      # scrub("�") would instead collapse a valid-but-truncated multibyte prefix into a single U+FFFD
      # (e.g. "\xE0\xA0" -> 1 vs Go's 2), so the per-byte block is required for byte-exact OPA output.
      # :reek:UtilityFunction
      def scrub_invalid_bytes(string)
        as_utf8 = string.encoding == ::Encoding::UTF_8 ? string : string.dup.force_encoding(::Encoding::UTF_8)
        as_utf8.valid_encoding? ? as_utf8 : as_utf8.scrub { |bad| "\u{FFFD}" * bad.bytesize }
      end

      def add_bindings(bindings)
        bindings.each do |(name, binding_value)|
          @bindings[name.to_s] = Value.from_ruby(binding_value)
        end
      end
    end
  end
end
