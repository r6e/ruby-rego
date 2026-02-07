# frozen_string_literal: true

require_relative "errors"

module Ruby
  module Rego
    # Normalizes error objects for structured result payloads.
    module ErrorPayload
      # @param error [Object]
      # @return [Object]
      def self.from(error)
        return error if error.is_a?(Hash) || error.is_a?(String)
        return error.to_h if error.is_a?(Error)
        return standard_error_payload(error) if error.is_a?(StandardError)

        error.to_s
      end

      # @param error [StandardError]
      # @return [Hash{Symbol => Object}]
      # :reek:ManualDispatch
      def self.standard_error_payload(error)
        payload = { message: error.message }
        return payload unless error.respond_to?(:location)

        location = error.location
        payload[:location] = location.to_s if location
        payload
      end

      private_class_method :standard_error_payload
    end
  end
end
