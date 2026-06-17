# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      module Times
        module GoLayout
          # The scalar field-reading primitives of the parser (getnum*, lookup): they read raw
          # digits/names from the value and advance the cursor, without owning any broken-down
          # field. Split from the per-token consumers and the driver so each file stays under
          # RubyCritic's complexity budget; the class path is unchanged.
          # :reek:InstanceVariableAssumption -- @value is set in Parser#initialize (parser.rb);
          # this reopen only reads/advances the already-established input cursor.
          class Parser
            private

            # Read a fixed (exactly two digits) or variable (one or two digits) decimal number,
            # advancing the value. nil when no digit is present, or fewer than two when fixed.
            def getnum(fixed)
              return nil unless digit?(@value[0])

              unless digit?(@value[1])
                return nil if fixed

                single = @value[0].to_i
                @value = @value[1..]
                return single
              end
              number = @value[0, 2].to_i
              @value = @value[2..]
              number
            end

            # Read a fixed (exactly three) or variable (one to three) digit day-of-year number.
            def getnum3(fixed)
              number = 0
              count = 0
              while count < 3 && digit?(@value[count])
                number = (number * 10) + @value[count].to_i
                count += 1
              end
              return nil if count.zero? || (fixed && count != 3)

              @value = @value[count..]
              number
            end

            # Exactly four digits (the long year). nil otherwise.
            def getnum4
              return nil unless (0..3).all? { |offset| digit?(@value[offset]) }

              number = @value[0, 4].to_i
              @value = @value[4..]
              number
            end

            # Case-insensitive longest-prefix match of the value against `names` (1-based result
            # like Go's month/weekday tables start). Returns the 1-based index or nil.
            def lookup(names)
              idx = names.index { |name| @value[0, name.length].to_s.casecmp?(name) }
              return nil if idx.nil?

              @value = @value[names[idx].length..]
              idx + 1
            end
          end
        end
      end
    end
  end
end
