# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"
require "rake"

RSpec::Core::RakeTask.new(:spec)

require "rubocop/rake_task"

RuboCop::RakeTask.new

desc "Run Reek"
task :reek do
  sh "bundle exec reek lib"
end

desc "Run RubyCritic"
task :rubycritic do
  sh "bundle exec rubycritic lib"
end

desc "Run Steep type checking"
task :steep do
  sh "bundle exec steep check"
end

desc "Run TypeProf for signatures"
task :typeprof do
  sh "bundle exec typeprof lib/**/*.rb"
end

desc "Run bundler-audit security checks"
task :bundler_audit do
  sh "bundle exec bundler-audit check --update"
end

task default: %i[spec rubocop reek rubycritic steep typeprof bundler_audit]
