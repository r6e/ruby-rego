# frozen_string_literal: true

require "json"
require "ruby/rego"

# Outcome and error reporting and formatting for rego-validate.
module RegoValidate
  # Emits human-readable or JSON output.
  class OutcomeEmitter
    # Emits JSON-formatted validation output.
    class JsonFormatter
      # @param stdout [IO]
      def initialize(stdout)
        @stdout = stdout
      end

      # @param outcome [Outcome]
      # @return [void]
      def emit(outcome)
        payload = OutcomePayload.new(outcome).to_h
        stdout.puts(JSON.generate(payload))
      end

      private

      attr_reader :stdout
    end

    # Emits human-readable validation output.
    class TextFormatter
      # @param stdout [IO]
      def initialize(stdout)
        @stdout = stdout
      end

      # @param outcome [Outcome]
      # @return [void]
      def emit(outcome)
        return stdout.puts("✓ Validation passed") if outcome.success?

        stdout.puts("✗ Validation failed:")
        outcome.errors.each { |error| stdout.puts("  - #{error}") }
      end

      private

      attr_reader :stdout
    end

    # Builds a JSON-serializable payload from an outcome.
    class OutcomePayload
      # @param outcome [Outcome]
      def initialize(outcome)
        @outcome = outcome
      end

      # @return [Hash{Symbol => Object}]
      def to_h
        return { success: true, result: normalize_json(outcome.value) } if outcome.success?

        { success: false, errors: outcome.errors }
      end

      private

      attr_reader :outcome

      def normalize_json(value)
        case value
        when Array
          normalize_array(value)
        when Hash
          normalize_hash(value)
        when Set
          normalize_set(value)
        else
          value
        end
      end

      def normalize_array(values)
        values.map { |item| normalize_json(item) }
      end

      def normalize_hash(values)
        values.transform_values { |item| normalize_json(item) }
      end

      def normalize_set(values)
        values.to_a.map { |item| normalize_json(item) }
      end
    end

    FORMATTERS = {
      "json" => JsonFormatter,
      "text" => TextFormatter
    }.freeze

    # Create an emitter for CLI output.
    #
    # @param stdout [IO]
    # @param format [String]
    def initialize(stdout, format: "text")
      @formatter = FORMATTERS.fetch(format, TextFormatter).new(stdout)
    end

    # Emit the outcome payload.
    #
    # @param outcome [Outcome]
    # @return [void]
    def emit(outcome)
      formatter.emit(outcome)
    end

    private

    attr_reader :formatter
  end

  # Formats and emits CLI errors to stderr/stdout.
  class ErrorReporter
    # Serializes error details for JSON output.
    class ErrorPayload
      # Build a payload for a CLI error message.
      #
      # @param message [String]
      # @return [ErrorPayload]
      def self.from_cli_error(message)
        new(message: message, type: "CLIError")
      end

      # Build a payload for a Rego error.
      #
      # @param error [Ruby::Rego::Error]
      # @return [ErrorPayload]
      def self.from_rego_error(error)
        new(message: error.message, type: error.class.name, location: error.location)
      end

      # @param message [String]
      # @param type [String]
      # @param location [Ruby::Rego::Location, nil]
      def initialize(message:, type:, location: nil)
        @message = message
        @type = type
        @location = location
      end

      # @return [Hash{Symbol => Object}]
      def to_h
        payload = { success: false, error: message, type: type }
        return payload unless location

        payload.merge(
          location: location.to_s,
          line: location.line,
          column: location.column
        )
      end

      private

      attr_reader :message, :type, :location
    end

    # Emits JSON-formatted error output.
    class JsonFormatter
      # @param stdout [IO]
      # @param stderr [IO]
      def initialize(stdout:, stderr:)
        @stdout = stdout
        @stderr = stderr
      end

      # @param message [String]
      # @param parser [OptionParser, nil]
      # @return [void]
      def error(message, _parser = nil)
        payload = ErrorPayload.from_cli_error(message).to_h
        stdout.puts(JSON.generate(payload))
      end

      # @param error [Ruby::Rego::Error]
      # @return [void]
      def rego_error(error)
        payload = ErrorPayload.from_rego_error(error).to_h
        stdout.puts(JSON.generate(payload))
      end

      private

      attr_reader :stdout, :stderr
    end

    # Emits text error output for CLI.
    class TextFormatter
      # @param stdout [IO]
      # @param stderr [IO]
      def initialize(stdout:, stderr:)
        @stdout = stdout
        @stderr = stderr
      end

      # @param message [String]
      # @param parser [OptionParser, nil]
      # @return [void]
      def error(message, parser = nil)
        stderr.puts("Error: #{message}")
        stderr.puts(parser) if parser
      end

      # @param error [Ruby::Rego::Error]
      # @return [void]
      def rego_error(error)
        location = error.location
        stderr.puts("Error: #{error.message}")
        stderr.puts("  at #{location}") if location
      end

      private

      attr_reader :stdout, :stderr
    end

    FORMATTERS = {
      "json" => JsonFormatter,
      "text" => TextFormatter
    }.freeze

    # Create an error reporter.
    #
    # @param stdout [IO]
    # @param stderr [IO]
    # @param format [String]
    def initialize(stdout:, stderr:, format: "text")
      @formatter = FORMATTERS.fetch(format, TextFormatter).new(stdout: stdout, stderr: stderr)
    end

    # Emit a generic CLI error.
    #
    # @param message [String]
    # @param parser [OptionParser, nil]
    # @return [void]
    def error(message, parser = nil)
      @formatter.error(message, parser)
    end

    # Emit a Ruby::Rego error with location details.
    #
    # @param error [Ruby::Rego::Error]
    # @return [void]
    def rego_error(error)
      @formatter.rego_error(error)
    end

    private

    attr_reader :formatter
  end
end
