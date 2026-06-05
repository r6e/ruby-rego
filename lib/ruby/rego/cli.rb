# frozen_string_literal: true

require "json"
require "optparse"
require "yaml"
require "ruby/rego"
require_relative "cli/options_parsing"
require_relative "cli/loading"
require_relative "cli/profiling"
require_relative "cli/evaluation"
require_relative "cli/reporting"

# CLI entrypoints and helpers for rego-validate.
module RegoValidate
  # CLI option values.
  Options = Struct.new(:policy, :config, :query, :format, :help, :yaml_aliases, :profile)

  # CLI option values.
  class Options
    # Check whether help output was requested.
    #
    # @return [Boolean]
    def help?
      help
    end

    # Check whether profiling output was requested.
    #
    # @return [Boolean]
    def profile?
      profile
    end
  end

  # Parsed options plus parser state and error details.
  ParseResult = Struct.new(:options, :parser, :error)

  # Parsed options plus parser state and error details.
  class ParseResult
    # Check whether parsing succeeded.
    #
    # @return [Boolean]
    def success?
      !error
    end

    # Report the parse error using the configured output format.
    #
    # @param stdout [IO]
    # @param stderr [IO]
    # @return [void]
    def report_error(stdout:, stderr:)
      reporter = ErrorReporter.new(stdout: stdout, stderr: stderr, format: options.format)
      reporter.error(error_message, parser)
    end

    private

    def error_message
      error ? error.message : "Invalid command-line options"
    end
  end

  # Captures the outcome of loading a config file.
  ConfigLoadResult = Struct.new(:value, :success)

  # Captures the outcome of loading a config file.
  class ConfigLoadResult
    # Check whether loading succeeded.
    #
    # @return [Boolean]
    def success?
      success
    end
  end

  # Policy evaluation outcome with optional error message.
  EvaluationResult = Struct.new(:outcome, :error_message)

  # Policy evaluation outcome with optional error message.
  class EvaluationResult
    # Check whether evaluation succeeded.
    #
    # @return [Boolean]
    def success?
      !!outcome && error_message.to_s.empty?
    end
  end

  # Normalized policy evaluation outcome.
  Outcome = Struct.new(:success, :value, :errors)

  # Normalized policy evaluation outcome.
  class Outcome
    # Check whether the outcome indicates success.
    #
    # @return [Boolean]
    def success?
      success
    end
  end

  # Command-line interface for validating inputs against a Rego policy.
  class CLI
    # Create a CLI instance.
    #
    # @param argv [Array<String>] command-line arguments
    # @param stdout [IO] output stream
    # @param stderr [IO] error stream
    def initialize(argv, stdout: $stdout, stderr: $stderr)
      @argv = argv
      @stdout = stdout
      @stderr = stderr
      @options = Options.new(format: "text", help: false, yaml_aliases: false, profile: false)
    end

    # Run the CLI and return an exit status.
    #
    # @return [Integer]
    def run
      perform_run
    rescue Ruby::Rego::Error => e
      handle_rego_error(e)
    rescue StandardError => e
      handle_unexpected_error(e)
    end

    private

    attr_reader :argv, :options, :stdout, :stderr

    def perform_run
      parse_result = OptionsParser.new(argv).parse
      return handle_parse_error(parse_result) unless parse_result.success?

      apply_parse_result(parse_result)
    end

    def apply_parse_result(parse_result)
      parser = parse_result.parser
      @options = parse_result.options
      return handle_help(parser) if options.help?
      return 2 unless required_options_present?(parser)

      handle_evaluation(parser)
    end

    def handle_evaluation(parser)
      evaluation = evaluate_policy(parser, profiler: options.profile? ? Profiler.new(stderr: stderr) : nil)
      outcome = evaluation.outcome
      return 2 unless evaluation.success? && outcome

      emit_outcome(outcome)
    end

    def emit_outcome(outcome)
      OutcomeEmitter.new(stdout, format: options.format).emit(outcome)
      outcome.success? ? 0 : 1
    end

    def handle_parse_error(parse_result)
      parse_result.report_error(stdout: stdout, stderr: stderr)
      2
    end

    def required_options_present?(parser)
      missing = OptionsValidator.new(options).missing_required
      return true if missing.empty?

      reporter.error("Missing required options: #{missing.join(", ")}", parser)
      false
    end

    def evaluate_policy(parser, profiler: nil)
      policy_source, config_result = SourceLoader.new(options: options, reporter: reporter, parser: parser).load
      return EvaluationResult.new unless policy_source && config_result.success?

      evaluation = PolicyEvaluator.new(policy_source, config_result.value, options.query, profiler: profiler).evaluate
      report_evaluation_error(evaluation, parser)
      evaluation
    end

    def report_evaluation_error(evaluation, parser)
      message = evaluation.error_message
      return unless message

      reporter.error(message, parser)
    end

    def handle_help(parser)
      if options.format == "json"
        stdout.puts(JSON.generate({ success: true, help: parser.to_s }))
      else
        stdout.puts(parser)
      end
      0
    end

    def reporter
      ErrorReporter.new(stdout: stdout, stderr: stderr, format: options.format)
    end

    def handle_rego_error(error)
      reporter.rego_error(error)
      2
    end

    def handle_unexpected_error(error)
      reporter.error("Unexpected error: #{error.message}")
      2
    end
  end
end
