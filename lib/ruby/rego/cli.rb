# frozen_string_literal: true

require "json"
require "optparse"
require "yaml"
require "ruby/rego"

# CLI entrypoints and helpers for rego-validate.
module RegoValidate
  # CLI option values.
  Options = Struct.new(:policy, :config, :query, :format, :help, :yaml_aliases, :profile, keyword_init: true)

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
  ParseResult = Struct.new(:options, :parser, :error, keyword_init: true)

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
  ConfigLoadResult = Struct.new(:value, :success, keyword_init: true)

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
  EvaluationResult = Struct.new(:outcome, :error_message, keyword_init: true)

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
  Outcome = Struct.new(:success, :value, :errors, keyword_init: true)

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

  # Parses CLI arguments into a structured options object.
  class OptionsParser
    VALID_FORMATS = %w[text json].freeze

    # Create an options parser.
    #
    # @param argv [Array<String>] command-line arguments
    def initialize(argv)
      @argv = argv
    end

    # Parse arguments into an options result.
    #
    # @return [ParseResult]
    def parse
      ParseResultBuilder.new(argv).call
    end

    private

    attr_reader :argv

    # Builds ParseResult objects from argv values.
    class ParseResultBuilder
      # @param argv [Array<String>]
      def initialize(argv)
        @argv = argv
      end

      # @return [ParseResult]
      def call
        # @type var options: Options
        options = Options.new(format: "text", help: false, yaml_aliases: false, profile: false)
        parse_with(options)
      end

      private

      attr_reader :argv

      def parse_with(options)
        parser = OptionDefinitions.new(options).build
        parser.parse!(@argv)
        ParseResult.new(options: options, parser: parser)
      rescue OptionParser::ParseError => e
        ParseResult.new(options: options, parser: parser, error: e)
      end
    end

    # Builds option definitions for OptionParser.
    class OptionDefinitions
      OPTION_BUILDERS = %i[
        add_policy_option
        add_config_option
        add_query_option
        add_format_option
        add_profile_option
        add_yaml_aliases_option
        add_help_option
      ].freeze

      # @param options [Options]
      def initialize(options)
        @options = options
      end

      # @return [OptionParser]
      def build
        OptionParser.new do |opts|
          opts.banner = "Usage: rego-validate --policy POLICY_FILE --config CONFIG_FILE [options]"
          apply_options(opts)
        end
      end

      private

      attr_reader :options

      def apply_options(opts)
        OPTION_BUILDERS.each { |builder| send(builder, opts) }
      end

      def add_policy_option(opts)
        opts.on("--policy FILE", "Rego policy file (required)") do |file|
          options.policy = file
        end
      end

      def add_config_option(opts)
        opts.on("--config FILE", "YAML/JSON config file (required)") do |file|
          options.config = file
        end
      end

      def add_query_option(opts)
        opts.on("--query QUERY", "Query path (optional, defaults to violations/errors)") do |query|
          options.query = query
        end
      end

      def add_format_option(opts)
        message = "Output format: #{OptionsParser::VALID_FORMATS.join(", ")} (default: text)"
        opts.on("--format FORMAT", OptionsParser::VALID_FORMATS, message) do |format|
          options.format = format
        end
      end

      def add_profile_option(opts)
        opts.on("--profile", "Emit evaluation profiling to stderr") do
          options.profile = true
        end
      end

      def add_help_option(opts)
        opts.on("-h", "--help", "Show this help") do
          options.help = true
        end
      end

      def add_yaml_aliases_option(opts)
        opts.on("--yaml-aliases", "Allow YAML aliases in config files") do
          options.yaml_aliases = true
        end
      end
    end
  end

  # Checks presence of required CLI options.
  class OptionsValidator
    # Create a validator for parsed options.
    #
    # @param options [Options]
    def initialize(options)
      @options = options
    end

    # List missing required flags.
    #
    # @return [Array<String>]
    def missing_required
      # @type var missing: Array[String]
      missing = []
      missing << "--policy" unless options.policy
      missing << "--config" unless options.config
      missing
    end

    private

    attr_reader :options
  end

  # Loads policy and input configuration files.
  class ConfigLoader
    JSON_EXTENSIONS = [".json"].freeze

    # Create a config loader.
    #
    # @param reporter [ErrorReporter]
    # @param parser [OptionParser]
    def initialize(reporter:, parser:, yaml_aliases:)
      @reporter = reporter
      @parser = parser
      @json_extensions = JSON_EXTENSIONS
      @yaml_aliases = yaml_aliases
    end

    # Read the policy file content.
    #
    # @param path [String]
    # @return [String, nil]
    def read_policy(path)
      read_file(path, "policy")
    end

    # Read and parse the config file content.
    #
    # @param path [String]
    # @return [ConfigLoadResult]
    def read_config(path)
      content = read_file(path, "config")
      return ConfigLoadResult.new(success: false) unless content

      parse_config(content, path)
    end

    private

    attr_reader :reporter, :parser, :json_extensions, :yaml_aliases

    def read_file(path, label)
      File.read(path)
    rescue Errno::ENOENT
      report_file_error(label, "not found", path)
      nil
    rescue Errno::EACCES
      report_file_error(label, "not readable", path)
      nil
    end

    def parse_config(content, path)
      value = parse_config_value(content, path)
      ConfigLoadResult.new(value: value, success: true)
    rescue JSON::ParserError, Psych::BadAlias, Psych::SyntaxError => e
      reporter.error("Invalid config file: #{e.message}", parser)
      ConfigLoadResult.new(success: false)
    end

    def parse_config_value(content, path)
      json_config?(path) ? JSON.parse(content) : YAML.safe_load(content, aliases: yaml_aliases)
    end

    def report_file_error(label, reason, path)
      reporter.error("#{label.capitalize} file #{reason}: #{path}", parser)
    end

    def json_config?(path)
      json_extensions.include?(File.extname(path).downcase)
    end
  end

  # Loads policy and config sources based on CLI options.
  class SourceLoader
    # @param options [Options]
    # @param reporter [ErrorReporter]
    # @param parser [OptionParser]
    def initialize(options:, reporter:, parser:)
      @options = options
      @loader = ConfigLoader.new(reporter: reporter, parser: parser, yaml_aliases: options.yaml_aliases)
    end

    # @return [Array<(String, ConfigLoadResult)>]
    def load
      policy_source = load_policy_source
      return [nil, ConfigLoadResult.new(success: false)] unless policy_source

      [policy_source, load_config]
    end

    private

    attr_reader :options, :loader

    def load_policy_source
      policy_path = options.policy
      return nil unless policy_path

      loader.read_policy(policy_path)
    end

    def load_config
      config_path = options.config
      return ConfigLoadResult.new(success: false) unless config_path

      loader.read_config(config_path)
    end
  end

  # Resolves default queries based on available rules.
  class DefaultQueryResolver
    DEFAULT_RULE_NAMES = %w[deny violations violation errors error].freeze
    FALLBACK_RULE_NAMES = %w[allow].freeze

    # @param compiled_module [Ruby::Rego::CompiledModule]
    def initialize(compiled_module)
      @compiled_module = compiled_module
      @rule_names = DEFAULT_RULE_NAMES + FALLBACK_RULE_NAMES
    end

    # @return [String, nil]
    def resolve
      rule_name = rule_names.find do |name|
        rule_available?(name)
      end
      return nil unless rule_name

      base = ["data", *package_path].join(".")
      "#{base}.#{rule_name}"
    end

    private

    attr_reader :compiled_module, :rule_names

    def rule_available?(name)
      compiled_module.has_rule?(name)
    end

    def package_path
      compiled_module.package_path
    end
  end
  private_constant :DefaultQueryResolver

  # Captures timing and memory statistics for policy evaluation.
  class Profiler
    # Holds a single profiler sample.
    Sample = Struct.new(:label, :duration_ms, :allocations, :memory_bytes, :top_objects, keyword_init: true)

    # Rendering helpers for profiler samples.
    class Sample
      def report_line
        parts = [
          "  #{label}: #{format_duration}",
          "allocs +#{allocations}",
          "mem #{format_bytes}"
        ]
        parts.join(", ")
      end

      def top_objects_line
        return nil if top_objects.empty?

        "  top allocations: #{top_objects.join(", ")}"
      end

      private

      def format_duration
        format("%.2f ms", duration_ms)
      end

      def format_bytes
        ByteFormatter.new(memory_bytes).render
      end
    end

    # Formats byte sizes for profiler output.
    class ByteFormatter
      def initialize(bytes)
        @sign = bytes.negative? ? "-" : "+"
        @size = bytes.abs
      end

      def render
        unit, value = if size < 1024
                        ["B", size.to_s]
                      elsif size < 1024 * 1024
                        ["KB", Kernel.format("%.2f", size / 1024.0)]
                      else
                        ["MB", Kernel.format("%.2f", size / (1024.0 * 1024.0))]
                      end
        "#{sign}#{value} #{unit}"
      end

      private

      attr_reader :sign, :size
    end

    # Captures a memory snapshot for diffing.
    class Snapshot
      class << self
        def capture
          require "objspace"
          build_snapshot(memsize: ObjectSpace.memsize_of_all, objects: ObjectSpace.count_objects)
        rescue LoadError, NoMethodError
          build_snapshot(memsize: 0, objects: empty_object_counts)
        end

        def capture_before
          capture
        end

        def capture_after
          capture
        end

        private

        def build_snapshot(memsize:, objects:)
          new(
            allocated: GC.stat[:total_allocated_objects],
            memsize: memsize,
            objects: objects
          )
        end

        def empty_object_counts
          {} # @type var objects: Hash[Symbol, Integer]
        end
      end

      def initialize(allocated:, memsize:, objects:)
        @allocated = allocated
        @memsize = memsize
        @objects = objects
      end

      attr_reader :allocated, :memsize, :objects

      def delta(other)
        Delta.new(
          allocations: other.allocated - allocated,
          memory_bytes: other.memsize - memsize,
          object_deltas: object_delta_map(other.objects)
        )
      end

      private

      def object_delta_map(after_objects)
        deltas = {} # @type var deltas: Hash[Symbol, Integer]
        after_objects.each { |key, count| add_delta(deltas, key, count) }
        deltas
      end

      def add_delta(deltas, key, count)
        return if Delta.skip_key?(key)

        delta = count - (objects[key] || 0)
        deltas[key] = delta if delta.positive?
      end
    end

    # Computes deltas between snapshots.
    class Delta
      SKIP_KEYS = %i[TOTAL FREE].freeze

      def self.skip_key?(key)
        SKIP_KEYS.include?(key)
      end

      def initialize(allocations:, memory_bytes:, object_deltas:)
        @allocations = allocations
        @memory_bytes = memory_bytes
        @object_deltas = object_deltas
      end

      attr_reader :allocations, :memory_bytes, :object_deltas

      def top_objects(limit: 3)
        object_deltas
          .sort_by { |(_, count)| -count }
          .first(limit)
          .map { |(key, count)| "#{key} +#{count}" }
      end
    end

    # Tracks measurement state for a single sample.
    class Measurement
      def initialize(label:, before:, start:)
        @label = label
        @before = before
        @start = start
      end

      def finish(after:, finish:)
        delta = before.delta(after)
        Sample.new(
          label: label,
          duration_ms: ((finish - start) * 1000.0),
          allocations: delta.allocations,
          memory_bytes: delta.memory_bytes,
          top_objects: delta.top_objects
        )
      end

      private

      attr_reader :before, :label, :start
    end

    # @param stderr [IO]
    def initialize(stderr: $stderr)
      @stderr = stderr
      @samples = [] # @type var @samples: Array[Sample]
      @clock = Process.method(:clock_gettime)
    end

    # @param label [String]
    # @return [Object]
    def measure(label)
      measurement = start_measurement(label)
      result = yield
      result
    ensure
      finish_measurement(measurement)
    end

    # @return [void]
    def report
      return if samples.empty?

      stderr.puts("Profile:")
      report_samples
      report_hotspot
    end

    private

    attr_reader :clock, :samples, :stderr

    def report_samples
      samples.each do |sample|
        stderr.puts(sample.report_line)
        top_line = sample.top_objects_line
        stderr.puts(top_line) if top_line
      end
    end

    def report_hotspot
      hotspot = samples.max_by(&:duration_ms)
      stderr.puts("  hotspot: #{hotspot.label}") if hotspot
    end

    def start_measurement(label)
      Measurement.new(
        label: label,
        before: Snapshot.capture_before,
        start: clock_time
      )
    end

    def finish_measurement(measurement)
      return unless measurement

      sample = measurement.finish(after: Snapshot.capture_after, finish: clock_time)
      samples << sample
    end

    def clock_time
      clock.call(Process::CLOCK_MONOTONIC)
    end
  end

  # Compiles and evaluates policies with a resolved query.
  class PolicyEvaluator
    # Create a policy evaluator.
    #
    # @param policy_source [String]
    # @param input [Object]
    # @param query [String, nil]
    def initialize(policy_source, input, query, profiler: nil)
      @policy_source = policy_source
      @input = input
      @query = query
      @profiler = profiler
    end

    # Compile and evaluate the policy using the resolved query.
    #
    # @return [EvaluationResult]
    def evaluate
      compiled_module = measure("compile") { Ruby::Rego.compile(policy_source) }
      query_path = resolve_query(compiled_module)
      return EvaluationResult.new(error_message: "No default validation rule found. Provide --query.") unless query_path

      build_evaluation(compiled_module, query_path)
    ensure
      profiler&.report
    end

    private

    attr_reader :policy_source, :input, :query, :profiler

    def resolve_query(compiled_module)
      query || DefaultQueryResolver.new(compiled_module).resolve
    end

    def build_evaluation(compiled_module, query_path)
      result = measure("evaluate") { evaluate_compiled(compiled_module, query_path) }
      outcome = OutcomeBuilder.new(result, query_path).build
      EvaluationResult.new(outcome: outcome)
    end

    def evaluate_compiled(compiled_module, query_path)
      Ruby::Rego::Evaluator.new(compiled_module, input: input, data: nil).evaluate(query_path)
    rescue Ruby::Rego::Error
      raise
    rescue StandardError => e
      raise Ruby::Rego::Error.new("Rego evaluation failed: #{e.message}", location: nil), cause: e
    end

    def measure(label, &)
      return yield unless profiler

      profiler.measure(label, &)
    end
  end

  # Builds a normalized outcome payload from evaluation results.
  class OutcomeBuilder
    # Create an outcome builder.
    #
    # @param result [Ruby::Rego::Result, nil]
    # @param query [String]
    def initialize(result, query)
      @result = result
      @query = query
    end

    # Build the normalized outcome.
    #
    # @return [Outcome]
    def build
      return undefined_outcome unless result
      return undefined_outcome if result.undefined?

      build_defined_outcome
    end

    private

    attr_reader :result, :query

    def build_defined_outcome
      value = defined_result.value.to_ruby
      errors = errors_for(value)
      Outcome.new(success: errors.empty?, value: value, errors: errors)
    end

    def errors_for(value)
      errors = errors_from_value(value)
      result_errors = defined_result.errors
      errors.concat(result_errors.map(&:to_s)) unless result_errors.empty?
      errors
    end

    def defined_result
      result || raise("Expected defined result")
    end

    def undefined_outcome
      Outcome.new(success: false, value: nil, errors: [format_rule_error("undefined")])
    end

    def errors_from_value(value)
      return [] if value == true

      errors_for_non_true(value)
    end

    def errors_for_non_true(value)
      scalar = scalar_error(value)
      return scalar unless value
      return collection_errors(value) if value.is_a?(Array) || value.is_a?(Set)
      return hash_errors(value) if value.is_a?(Hash)

      scalar
    end

    def scalar_error(value)
      [format_rule_error(value)]
    end

    def collection_errors(value)
      value.to_a.map { |item| format_rule_error(item) }
    end

    def hash_errors(value)
      return [] if value.empty?

      [format_rule_error(value)]
    end

    def format_rule_error(value)
      "Rule '#{rule_name}' returned: #{value.inspect}"
    end

    def rule_name
      @rule_name ||= query.to_s.split(".").last
    end
  end

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
