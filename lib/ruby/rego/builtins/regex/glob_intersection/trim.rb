# frozen_string_literal: true

# rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

module Ruby
  module Rego
    module Builtins
      module Regex
        # Shared-affix trimming and the flag-count cap (gintersect.trimGlobs).
        # Lives apart from the intersection core so the main file stays under
        # RubyCritic's complexity budget. Reopens GlobIntersection; match? and
        # GlobError live in the main file (loaded first).
        module GlobIntersection
          def self.trim_globs(lhs, rhs)
            left = trim_prefix(lhs, rhs)
            return [[], [], false] if left.nil?

            suffix = trim_suffix(lhs, rhs, left)
            return [[], [], false] if suffix.nil?

            right_lhs, right_rhs = suffix
            [lhs[left..right_lhs] || [], rhs[left..right_rhs] || [], true]
          end
          private_class_method :trim_globs

          # @return [Integer, nil] index after the trimmed prefix, or nil on mismatch
          def self.trim_prefix(lhs, rhs)
            left = 0
            while left < lhs.length && left < rhs.length && !lhs[left].flagged? && !rhs[left].flagged?
              return nil unless match?(lhs[left], rhs[left])

              left += 1
            end
            # Leave one prefix token untrimmed so neither glob becomes empty.
            left.positive? ? left - 1 : left
          end
          private_class_method :trim_prefix

          # @return [Array(Integer, Integer), nil] last kept indices, or nil on mismatch
          def self.trim_suffix(lhs, rhs, left)
            right_lhs = lhs.length - 1
            right_rhs = rhs.length - 1
            while right_lhs >= 0 && right_lhs >= left && right_rhs >= 0 && right_rhs >= left &&
                  !lhs[right_lhs].flagged? && !rhs[right_rhs].flagged?
              return nil unless match?(lhs[right_lhs], rhs[right_rhs])

              right_lhs -= 1
              right_rhs -= 1
            end
            # Leave one suffix token untrimmed so neither glob becomes empty.
            right_lhs < lhs.length - 1 ? [right_lhs + 1, right_rhs + 1] : [right_lhs, right_rhs]
          end
          private_class_method :trim_suffix

          def self.ensure_within_flag_limit(lhs, rhs)
            flags_lhs = lhs.count(&:flagged?)
            flags_rhs = rhs.count(&:flagged?)
            return if [flags_lhs, flags_rhs].min <= MAX_GLOB_FLAGS

            raise GlobError, "too many flags to intersect"
          end
          private_class_method :ensure_within_flag_limit
        end
      end
    end
  end
end
# rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
