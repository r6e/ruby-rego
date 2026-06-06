# frozen_string_literal: true

require "spec_helper"

# regex.find_all_string_submatch_n and regex.template_match. Expected values
# pinned against `opa eval` (OPA 1.17.0).

SUBMATCH_POLICY = <<~REGO
  package t

  result := regex.find_all_string_submatch_n(input.pattern, input.string, input.n)
REGO

TEMPLATE_POLICY = <<~REGO
  package t

  result := regex.template_match(input.template, input.string, input.ds, input.de)
REGO

# rubocop:disable Metrics/BlockLength
RSpec.describe "regex.find_all_string_submatch_n and regex.template_match" do
  def submatch(pattern, string, count)
    evaluate_policy(SUBMATCH_POLICY, input: { "pattern" => pattern, "string" => string, "n" => count },
                                     query: "data.t.result").value.to_ruby
  end

  def template(tmpl, string, delim_start = "{", delim_end = "}")
    result = evaluate_policy(TEMPLATE_POLICY,
                             input: { "template" => tmpl, "string" => string,
                                      "ds" => delim_start, "de" => delim_end },
                             query: "data.t.result")
    result&.value&.to_ruby
  end

  describe "find_all_string_submatch_n" do
    it "returns full match plus submatches for each match (n = -1)" do
      expect(submatch("a(.)c", "abc axc", -1)).to eq([%w[abc b], %w[axc x]])
    end

    it "limits the number of matches when n is positive" do
      expect(submatch("a(.)c", "abc axc", 1)).to eq([%w[abc b]])
    end

    it "returns an empty array when n is zero" do
      expect(submatch("a(.)c", "abc axc", 0)).to eq([])
    end

    it "returns an empty array when there is no match" do
      expect(submatch("z(.)z", "abc", -1)).to eq([])
    end

    it "returns single-element rows when the pattern has no groups" do
      expect(submatch("a.c", "abc axc", -1)).to eq([["abc"], ["axc"]])
    end

    it "yields empty strings for non-participating alternation groups" do
      expect(submatch("(a)|(b)", "ab", -1)).to eq([["a", "a", ""], ["b", "", "b"]])
    end
  end

  describe "template_match" do
    it "matches a delimited regex section against the string" do
      expect(template("urn:foo:{[a-z]+}", "urn:foo:bar")).to be(true)
    end

    it "fails when the regex section does not match" do
      expect(template("urn:foo:{[a-z]+}", "urn:foo:123")).to be(false)
    end

    it "matches a template with no sections literally" do
      expect(template("foobar", "foobar")).to be(true)
    end

    it "anchors the whole string (no partial match)" do
      expect(template("{[0-9]+}", "12a")).to be(false)
    end

    it "treats literal regex metacharacters literally" do
      expect(template("a+b", "a+b")).to be(true)
      expect(template("a+b", "aaab")).to be(false)
    end

    it "supports custom single-character delimiters" do
      expect(template("aX[0-9]+Yc", "a99c", "X", "Y")).to be(true)
    end

    it "matches an empty section against the empty string" do
      expect(template("{}", "")).to be(true)
    end

    it "scopes alternation to its section (a section groups its content)" do
      # `{a|b}c` means `(a|b)c`, not `a|(bc)`.
      expect(template("{a|b}c", "bc")).to be(true)
      expect(template("{a|b}c", "a")).to be(false)
      expect(template("{a|b}c", "xbc")).to be(false)
    end

    # OPA validates delimiters by byte length and requires balanced sections;
    # these all resolve to undefined.
    it "is undefined for a multi-byte (single-character) delimiter" do
      expect(template("a£x£c", "abc", "£", "£")).to be_nil
    end

    it "is undefined for a multi-character delimiter" do
      expect(template("a{b}c", "a9c", "<<", ">>")).to be_nil
    end

    it "is undefined for an empty delimiter" do
      expect(template("a[0-9]c", "a9c", "", "")).to be_nil
    end

    it "is undefined for an unbalanced opening delimiter" do
      expect(template("a{b", "axb")).to be_nil
    end

    it "is undefined for a stray closing delimiter" do
      expect(template("a}b", "a}b")).to be_nil
    end
  end
end
# rubocop:enable Metrics/BlockLength
