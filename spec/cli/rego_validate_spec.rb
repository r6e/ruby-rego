# frozen_string_literal: true

require "spec_helper"
require "stringio"
require "tmpdir"
require "ruby/rego/cli"

RSpec.shared_context "rego cli helpers" do
  let(:policy_source) do
    <<~REGO
      package example
      default allow := false
      allow { input.user == "admin" }
    REGO
  end

  def write_temp_file(dir, name, contents)
    path = File.join(dir, name)
    File.write(path, contents)
    path
  end

  def run_cli(args)
    stdout = StringIO.new
    stderr = StringIO.new
    status = RegoValidate::CLI.new(args, stdout: stdout, stderr: stderr).run
    { status: status, stdout: stdout.string, stderr: stderr.string }
  end
end

RSpec.describe "RegoValidate::CLI success" do
  include_context "rego cli helpers"

  it "returns success for allow policies" do
    Dir.mktmpdir do |dir|
      policy_path = write_temp_file(dir, "policy.rego", policy_source)
      config_path = write_temp_file(dir, "config.json", JSON.generate({ "user" => "admin" }))

      result = run_cli(["--policy", policy_path, "--config", config_path])

      expect(result[:status]).to eq(0)
      expect(result[:stdout]).to include("Validation passed")
    end
  end

  it "returns failure and prints errors when allow is false" do
    Dir.mktmpdir do |dir|
      policy_path = write_temp_file(dir, "policy.rego", policy_source)
      config_path = write_temp_file(dir, "config.json", JSON.generate({ "user" => "bob" }))

      result = run_cli(["--policy", policy_path, "--config", config_path])

      expect(result[:status]).to eq(1)
      expect(result[:stdout]).to include("Validation failed")
    end
  end
end

RSpec.describe "RegoValidate::CLI profiling" do
  include_context "rego cli helpers"

  it "profiles when objspace is unavailable" do
    allow(Kernel).to receive(:require).and_wrap_original do |original, name|
      raise LoadError, "objspace unavailable" if name == "objspace"

      original.call(name)
    end

    Dir.mktmpdir do |dir|
      policy_path = write_temp_file(dir, "policy.rego", policy_source)
      config_path = write_temp_file(dir, "config.json", JSON.generate({ "user" => "admin" }))

      result = run_cli(["--policy", policy_path, "--config", config_path, "--profile"])

      expect(result[:status]).to eq(0)
      expect(result[:stderr]).to include("Profile:")
    end
  end
end

RSpec.describe "RegoValidate::CLI errors" do
  include_context "rego cli helpers"

  it "emits json errors for missing required options" do
    result = run_cli(["--config", "missing.json", "--format", "json"])

    expect(result[:status]).to eq(2)
    payload = JSON.parse(result[:stdout])
    expect(payload["success"]).to be(false)
    expect(payload["error"]).to include("Missing required options")
  end

  it "reports missing policy files" do
    Dir.mktmpdir do |dir|
      config_path = write_temp_file(dir, "config.json", JSON.generate({ "user" => "admin" }))
      missing_policy = File.join(dir, "missing.rego")

      result = run_cli(["--policy", missing_policy, "--config", config_path])

      expect(result[:status]).to eq(2)
      expect(result[:stderr]).to include("Policy file not found")
    end
  end
end

RSpec.describe "RegoValidate::CLI json output" do
  include_context "rego cli helpers"

  it "returns json output when requested" do
    Dir.mktmpdir do |dir|
      policy_path = write_temp_file(dir, "policy.rego", policy_source)
      config_path = write_temp_file(dir, "config.json", JSON.generate({ "user" => "admin" }))

      result = run_cli(["--policy", policy_path, "--config", config_path, "--format", "json"])

      expect(result[:status]).to eq(0)
      payload = JSON.parse(result[:stdout])
      expect(payload["success"]).to be(true)
      expect(payload["result"]).to be(true)
    end
  end

  it "reports invalid json config files" do
    Dir.mktmpdir do |dir|
      policy_path = write_temp_file(dir, "policy.rego", policy_source)
      config_path = write_temp_file(dir, "config.json", "{invalid-json")

      result = run_cli(["--policy", policy_path, "--config", config_path, "--format", "json"])

      expect(result[:status]).to eq(2)
      payload = JSON.parse(result[:stdout])
      expect(payload["success"]).to be(false)
      expect(payload["error"]).to include("Invalid config file")
    end
  end
end
