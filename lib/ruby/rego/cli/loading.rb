# frozen_string_literal: true

require "json"
require "yaml"
require_relative "../builtins/codecs/json_decoder"

# Policy and configuration source loading for rego-validate.
module RegoValidate
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
    rescue Ruby::Rego::Builtins::Codecs::JsonDecoder::ParseError,
           Psych::BadAlias, Psych::SyntaxError => e
      reporter.error("Invalid config file: #{e.message}", parser)
      ConfigLoadResult.new(success: false)
    end

    # JSON input/data parses through the gem's strict JsonDecoder so a number keeps OPA's
    # arbitrary-precision json.Number text (1.50 stays 1.50; a large 1e999 stays a usable number rather
    # than collapsing to Float and an unrepresentable comparison). YAML input still uses YAML.safe_load,
    # which collapses numbers to Float — a follow-up will route it through the yaml ScalarResolver.
    def parse_config_value(content, path)
      if json_config?(path)
        Ruby::Rego::Builtins::Codecs::JsonDecoder.parse(content)
      else
        YAML.safe_load(content,
                       aliases: yaml_aliases)
      end
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
end
