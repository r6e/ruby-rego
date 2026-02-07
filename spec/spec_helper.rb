# frozen_string_literal: true

require "simplecov"
SimpleCov.start do
  add_filter "/spec/"
end

require "factory_bot"
require "json"
require "yaml"
require "ruby/rego"

module SpecSupport
  # Shared helpers for loading test fixtures.
  module FixtureHelpers
    def fixture_path(*segments)
      File.join(__dir__, "fixtures", *segments)
    end

    def read_fixture(*segments)
      File.read(fixture_path(*segments))
    end

    def load_json_fixture(*segments)
      JSON.parse(read_fixture(*segments))
    end

    def load_yaml_fixture(*segments, aliases: false)
      YAML.safe_load(read_fixture(*segments), aliases: aliases)
    end
  end

  # Convenience helpers for parsing and evaluation.
  module PolicyHelpers
    def parse_policy(source)
      Ruby::Rego.parse(source)
    end

    def evaluate_policy(source, input: {}, data: {}, query: nil)
      Ruby::Rego.evaluate(source, input: input, data: data, query: query)
    end
  end
end

RSpec::Matchers.define :match_ast do |klass, attrs = {}|
  match do |actual|
    actual.is_a?(klass) && attrs.all? { |name, value| actual.public_send(name) == value }
  end

  failure_message do |actual|
    "expected #{actual.inspect} to be a #{klass} with #{attrs.inspect}"
  end
end

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.include FactoryBot::Syntax::Methods
  config.include SpecSupport::FixtureHelpers
  config.include SpecSupport::PolicyHelpers
  config.before(:suite) do
    FactoryBot.find_definitions
  end
end
