# frozen_string_literal: true

# rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Naming/PredicateMethod

module Ruby
  module Rego
    module Builtins
      module Regex
        # Reopens GlobIntersection to host the recursive intersection engine. Lives
        # apart from the tokenizer/trim core so the main file stays under
        # RubyCritic's complexity budget. GlobError, MAX_WORK, and match? live in
        # the main file (loaded first, before this require_relative).
        module GlobIntersection
          # Recursive intersection engine (gintersect.intersect*). Instance state holds
          # the work budget so the recursion can bail out on pathological input.
          class Intersector
            def initialize
              @work = 0
            end

            # Walks both globs while unflagged tokens match; defers to the special
            # handlers once a flagged token appears.
            def intersect_normal(lhs, rhs)
              index1 = 0
              index2 = 0
              while index1 < lhs.length && index2 < rhs.length
                charge_work
                token_lhs = lhs[index1]
                token_rhs = rhs[index2]
                if token_lhs.flagged? || token_rhs.flagged?
                  return intersect_special(lhs[index1..] || [],
                                           rhs[index2..] || [])
                end
                return false unless GlobIntersection.match?(token_lhs, token_rhs)

                index1 += 1
                index2 += 1
              end
              index1 == lhs.length && index2 == rhs.length
            end

            private

            def charge_work
              @work += 1
              raise GlobError, "intersection too expensive" if @work > MAX_WORK
            end

            # At least one of lhs[0]/rhs[0] is flagged. Both arrays are non-empty:
            # intersect_normal only dispatches here from inside its bounds check.
            def intersect_special(lhs, rhs)
              return dispatch(lhs, rhs) if lhs[0].flagged?

              dispatch(rhs, lhs)
            end

            def dispatch(flagged, other)
              flagged[0].flag == :plus ? intersect_plus(flagged, other) : intersect_star(flagged, other)
            end

            # plussed[0].flag == :plus.
            def intersect_plus(plussed, other)
              return false unless GlobIntersection.match?(plussed[0], other[0])
              # Either plussed[0] gobbles other[0]...
              return true if intersect_star(plussed, other[1..] || [])

              # ...or a flagged other[0] gobbles plussed[0] entirely.
              other[0].flagged? && intersect_normal(plussed[1..] || [], other)
            end

            # starred[0].flag == :star: gobble tokens from other until the remainder
            # intersects starred[1..].
            def intersect_star(starred, other)
              star_token = starred[0]
              next_atom = starred[1]
              other.each_with_index do |token, index|
                charge_work
                if next_atom && GlobIntersection.match?(token, next_atom)
                  return true if intersect_normal(starred[1..] || [], other[index..] || [])
                  return false unless GlobIntersection.match?(token, star_token)
                elsif !GlobIntersection.match?(token, star_token)
                  return false
                end
              end
              next_atom.nil?
            end
          end
        end
      end
    end
  end
end
# rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Naming/PredicateMethod
