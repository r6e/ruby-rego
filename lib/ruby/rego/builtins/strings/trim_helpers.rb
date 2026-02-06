# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        def self.trim_regex(cutset_text, mode:)
          escaped = Regexp.escape(cutset_text)
          Regexp.new(trim_patterns(escaped, mode).join("|"))
        end
        private_class_method :trim_regex

        def self.trimmed_text(string, cutset, context)
          name, mode = trim_context(context)
          string_text, cutset_text = trim_inputs(string, cutset, name)
          apply_trim_or_original(string_text, cutset_text, mode)
        end
        private_class_method :trimmed_text

        def self.trim_context(context)
          [context.fetch(:name), context.fetch(:mode)]
        end
        private_class_method :trim_context

        def self.trim_inputs(string, cutset, name)
          [
            string_value(string, context: "#{name} string"),
            string_value(cutset, context: "#{name} cutset")
          ]
        end
        private_class_method :trim_inputs

        def self.apply_trim_or_original(string_text, cutset_text, mode)
          return string_text if cutset_text.empty?

          apply_trim(string_text, cutset_text, mode)
        end
        private_class_method :apply_trim_or_original

        def self.apply_trim(string_text, cutset_text, mode)
          string_text.gsub(trim_regex(cutset_text, mode: mode), "")
        end
        private_class_method :apply_trim

        def self.trim_patterns(escaped, mode)
          case mode
          when :left
            ["\\A[#{escaped}]+"]
          when :right
            ["[#{escaped}]+\\z"]
          when :both
            ["\\A[#{escaped}]+", "[#{escaped}]+\\z"]
          else
            raise ArgumentError, "Unknown trim mode: #{mode}"
          end
        end
        private_class_method :trim_patterns
      end
    end
  end
end
