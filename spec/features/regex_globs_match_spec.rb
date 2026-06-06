# frozen_string_literal: true

require "spec_helper"

# regex.globs_match(glob1, glob2): true when the two restricted-regex globs share a
# common non-empty match. A faithful port of OPA's gintersect library — expected
# values (including its quirks) pinned against `opa eval` (OPA 1.17.0).

GLOBS_MATCH_POLICY = <<~REGO
  package t

  result := regex.globs_match(input.a, input.b)
REGO

# rubocop:disable Metrics/BlockLength
RSpec.describe "regex.globs_match" do
  def globs(glob1, glob2)
    result = evaluate_policy(GLOBS_MATCH_POLICY, input: { "a" => glob1, "b" => glob2 }, query: "data.t.result")
    result&.value&.to_ruby
  end

  describe "literals, dot, and character classes" do
    it "matches identical literals and rejects disjoint ones" do
      expect(globs("abc", "abc")).to be(true)
      expect(globs("abc", "abd")).to be(false)
    end

    it "treats . as any single character" do
      expect(globs("a.c", "abc")).to be(true)
      expect(globs("a.c", "abd")).to be(false)
    end

    it "intersects character classes by overlap" do
      expect(globs("[a-c]", "b")).to be(true)
      expect(globs("[a-c]", "d")).to be(false)
      expect(globs("[a-c]x", "[b-e]x")).to be(true)
      expect(globs("[a-c]", "[x-z]")).to be(false)
    end
  end

  describe "star (0+) and plus (1+) flags" do
    it "lets a starred token match zero occurrences in the middle" do
      expect(globs("a*", "a")).to be(true)
      expect(globs("a*b", "b")).to be(true)
      expect(globs("a*b*c", "abc")).to be(true)
    end

    it "requires plus to match at least one" do
      expect(globs("a+", "a")).to be(true)
      expect(globs("a+", "")).to be(false)
      expect(globs("a+b+", "ab")).to be(true)
    end

    it "excludes the empty string (a* does not intersect the empty glob)" do
      expect(globs("a*", "")).to be(false)
    end

    it "intersects overlapping wildcard tails" do
      expect(globs(".*", "abc")).to be(true)
      expect(globs("a.*", "a.b.*")).to be(true)
      expect(globs("a.*", "b.*")).to be(false)
    end

    # gintersect quirk: intersectNormal exhausts the shorter glob before the
    # trailing `*` token gets its zero-match. OPA returns false here.
    it "does not zero-match a trailing star against a shorter glob (gintersect quirk)" do
      expect(globs("abc.*", "abc")).to be(false)
      expect(globs("abc.*", "abcd")).to be(true)
    end
  end

  describe "empty globs and escapes" do
    it "treats two empty globs as matching" do
      expect(globs("", "")).to be(true)
      expect(globs("", "a")).to be(false)
    end

    it "matches the README example abab" do
      expect(globs(".b.b", "a.a.")).to be(true)
    end

    it "rejects disjoint character-class languages" do
      expect(globs("[a-z]+", "[0-9]*")).to be(false)
    end

    it "treats a backslash-escaped special symbol as a literal" do
      expect(globs("a\\.c", "a.c")).to be(true)  # literal "." matches the dot
      expect(globs("a\\.c", "axc")).to be(false) # literal "." does not match "x"
    end
  end

  describe "invalid globs are undefined" do
    it "rejects a flag with no preceding atom" do
      expect(globs("*abc", "x")).to be_nil
    end

    it "rejects an unterminated character class" do
      expect(globs("[abc", "a")).to be_nil
    end

    it "rejects a stray class-close bracket" do
      expect(globs("a]", "a]")).to be_nil
    end
  end

  describe "DoS bounds yield undefined (gintersect is exponential; no Go context here)" do
    bounds = Ruby::Rego::Builtins::Regex::GlobIntersection

    it "rejects a glob exceeding the source-length cap" do
      expect(globs("a" * (bounds::MAX_GLOB_SOURCE + 1), "a")).to be_nil
    end

    it "rejects globs whose smaller flag count exceeds the cap" do
      # Distinct atoms so Simplify does not collapse them into one flagged token.
      flagged = (0..bounds::MAX_GLOB_FLAGS).map { |i| "#{(97 + i).chr}*" }.join
      expect(globs(flagged, flagged)).to be_nil
    end

    it "rejects character-class ranges that cumulatively expand past the cap" do
      expect(globs("[A-\u{10FFFF}]", "a")).to be_nil
    end

    # Regression: a range spanning the UTF-16 surrogate block must not raise
    # (codepoints are stored as integers, never String#chr'd).
    it "matches a real character inside a surrogate-spanning range" do
      expect(globs("[A-\u{186A0}]", "a")).to be(true)
    end
  end
end
# rubocop:enable Metrics/BlockLength
