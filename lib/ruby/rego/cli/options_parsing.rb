# frozen_string_literal: true

require "optparse"

# Command-line option parsing and validation for rego-validate.
module RegoValidate
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
end
