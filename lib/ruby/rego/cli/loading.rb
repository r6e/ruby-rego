# frozen_string_literal: true

require "json"
require "yaml"
require "ruby/rego"

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
end
