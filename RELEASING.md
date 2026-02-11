# Releasing Ruby::Rego

## 1) Prepare the release

- Update [lib/ruby/rego/version.rb](lib/ruby/rego/version.rb) with the new version.
- Update [CHANGELOG.md](CHANGELOG.md) with notable changes and release date.
- Run the full suite locally:
  - `bundle exec rspec`
  - `bundle exec rubocop --format simple --no-color`
  - `bundle exec reek lib`
  - `bundle exec steep check`
  - `bundle exec typeprof lib/**/*.rb`
- Verify coverage is above 90% in `coverage/`.

## 2) Build and validate the gem

- Build the gem:
  - `gem build ruby-rego.gemspec`
- Install the built gem locally:
  - `gem install ./ruby-rego-<version>.gem`
- Smoke test the CLI:
  - `rego-validate --policy examples/validation_policy.rego --config examples/sample_config.yaml`

## 3) Tag and publish

- Create a signed tag:
  - `git tag -a v<version> -m "Release v<version>"`
- Push tags and main:
  - `git push origin main --tags`
- Publish to RubyGems:
  - `gem push ruby-rego-<version>.gem`

## 4) Post-release checks

- Confirm the release appears on RubyGems.
- Confirm the GitHub Pages docs deployed successfully.
- Create a GitHub release with release notes from the changelog.
