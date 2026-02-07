# frozen_string_literal: true

require "json"
require "open3"
require "tmpdir"

# rubocop:disable Metrics/BlockLength
RSpec.describe "rego-validate CLI" do
  let(:policy_source) do
    <<~REGO
      package example
      default allow = false
      allow { input.user == "admin" }
    REGO
  end

  def run_cli(*args)
    command = ["bundle", "exec", "ruby", "exe/rego-validate", *args]
    Open3.capture3(*command)
  end

  it "returns success for allow policies by default" do
    Dir.mktmpdir do |dir|
      policy_path = File.join(dir, "policy.rego")
      config_path = File.join(dir, "config.json")
      File.write(policy_path, policy_source)
      File.write(config_path, JSON.generate({ "user" => "admin" }))

      stdout, _stderr, status = run_cli("--policy", policy_path, "--config", config_path)

      expect(status.exitstatus).to eq(0)
      expect(stdout).to include("Validation passed")
    end
  end

  it "returns failure in json format when allow is false" do
    Dir.mktmpdir do |dir|
      policy_path = File.join(dir, "policy.rego")
      config_path = File.join(dir, "config.json")
      File.write(policy_path, policy_source)
      File.write(config_path, JSON.generate({ "user" => "bob" }))

      stdout, _stderr, status = run_cli(
        "--policy", policy_path,
        "--config", config_path,
        "--query", "data.example.allow",
        "--format", "json"
      )

      expect(status.exitstatus).to eq(1)
      payload = JSON.parse(stdout)
      expect(payload["success"]).to be(false)
      expect(payload["errors"]).to be_an(Array)
      expect(payload["errors"]).not_to be_empty
    end
  end

  it "fails when required options are missing" do
    Dir.mktmpdir do |dir|
      config_path = File.join(dir, "config.json")
      File.write(config_path, JSON.generate({ "user" => "admin" }))

      _stdout, stderr, status = run_cli("--config", config_path)

      expect(status.exitstatus).to eq(2)
      expect(stderr).to include("Missing required options")
    end
  end

  it "prints usage when help is requested" do
    stdout, _stderr, status = run_cli("--help")

    expect(status.exitstatus).to eq(0)
    expect(stdout).to include("Usage: rego-validate")
  end

  it "returns json help when format is json" do
    stdout, _stderr, status = run_cli("--help", "--format", "json")

    expect(status.exitstatus).to eq(0)
    payload = JSON.parse(stdout)
    expect(payload["success"]).to be(true)
    expect(payload["help"]).to include("Usage: rego-validate")
  end

  it "fails with a helpful error when config is invalid" do
    Dir.mktmpdir do |dir|
      policy_path = File.join(dir, "policy.rego")
      config_path = File.join(dir, "config.json")
      File.write(policy_path, policy_source)
      File.write(config_path, "{invalid-json")

      _stdout, stderr, status = run_cli("--policy", policy_path, "--config", config_path)

      expect(status.exitstatus).to eq(2)
      expect(stderr).to include("Invalid config file")
    end
  end

  it "returns json errors when format is json" do
    Dir.mktmpdir do |dir|
      config_path = File.join(dir, "config.json")
      File.write(config_path, JSON.generate({ "user" => "admin" }))

      stdout, _stderr, status = run_cli("--format", "json", "--config", config_path)

      expect(status.exitstatus).to eq(2)
      payload = JSON.parse(stdout)
      expect(payload["success"]).to be(false)
      expect(payload["error"]).to include("Missing required options")
    end
  end

  it "returns json errors for invalid config when format is json" do
    Dir.mktmpdir do |dir|
      policy_path = File.join(dir, "policy.rego")
      config_path = File.join(dir, "config.json")
      File.write(policy_path, policy_source)
      File.write(config_path, "{invalid-json")

      stdout, _stderr, status = run_cli(
        "--policy", policy_path,
        "--config", config_path,
        "--format", "json"
      )

      expect(status.exitstatus).to eq(2)
      payload = JSON.parse(stdout)
      expect(payload["success"]).to be(false)
      expect(payload["error"]).to include("Invalid config file")
    end
  end

  it "defaults to deny rules when present" do
    deny_policy = <<~REGO
      package example
      deny := ["port 22 should not be exposed"]
    REGO

    Dir.mktmpdir do |dir|
      policy_path = File.join(dir, "policy.rego")
      config_path = File.join(dir, "config.json")
      File.write(policy_path, deny_policy)
      File.write(config_path, JSON.generate({}))

      stdout, _stderr, status = run_cli("--policy", policy_path, "--config", config_path)

      expect(status.exitstatus).to eq(1)
      expect(stdout).to include("Rule 'deny' returned")
    end
  end
end
# rubocop:enable Metrics/BlockLength
