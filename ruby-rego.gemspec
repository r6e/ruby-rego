# frozen_string_literal: true

require_relative "lib/ruby/rego/version"

Gem::Specification.new do |spec|
  spec.name = "ruby-rego"
  spec.version = Ruby::Rego::VERSION
  spec.authors = ["Rob Trame"]
  spec.email = ["me@r6e.dev"]

  spec.summary = "Pure Ruby implementation of the OPA Rego policy language with a CLI."
  spec.description = "Ruby::Rego provides a pure Ruby parser, compiler, and evaluator for the Open " \
                     "Policy Agent Rego language. It targets a clean, idiomatic Ruby API, " \
                     "deterministic evaluation, and a CLI for validation workflows."
  spec.homepage = "https://github.com/r6e/ruby-rego"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["documentation_uri"] = "https://r6e.github.io/ruby-rego"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore .rspec spec/ .github/ .rubocop.yml])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Default gems that became separately installable in newer Rubies; the library
  # requires them at load time (json across the evaluator/CLI; base64/cgi for the
  # encoding builtins; digest/openssl for the crypto builtins; ipaddr for the net builtins).
  spec.add_dependency "base64"
  spec.add_dependency "cgi"
  spec.add_dependency "digest"
  spec.add_dependency "ipaddr"
  spec.add_dependency "json"
  spec.add_dependency "openssl"
  # tzinfo (with bundled tzinfo-data) for the IANA-timezone forms of the time builtins
  # (time.date/clock/weekday). tzinfo-data pins the IANA database so results don't depend on the
  # host's system zoneinfo version — matching OPA, which compiles in its own tzdata — and avoids a
  # TZInfo::DataSourceNotFound crash on hosts without system zoneinfo (Windows, minimal containers).
  spec.add_dependency "tzinfo", "~> 2.0"
  spec.add_dependency "tzinfo-data"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
