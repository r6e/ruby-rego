# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in regex helpers (regex.template_match).
      module Regex
        # `regex.template_match(template, string, delim_start, delim_end)` — the
        # template is literal text with delimited regex sections (`{...}` by default).
        # OPA requires each delimiter to be a single character; anything else (empty or
        # multi-character) or an unbalanced section yields undefined.
        #
        # @return [Ruby::Rego::BooleanValue]
        # :reek:LongParameterList
        # :reek:TooManyStatements
        def self.template_match(template_value, string_value, delim_start_value, delim_end_value)
          context = "regex.template_match"
          template = string_arg(template_value, context)
          string = string_arg(string_value, context)
          delim_start = single_delimiter(delim_start_value, context)
          delim_end = single_delimiter(delim_end_value, context)
          assert_source_length(template, context)
          regexp = compile_pattern(template_source(template, delim_start, delim_end, context), context).first
          guarded(context) { BooleanValue.new(regexp.match?(string)) }
        end

        # @return [String] the single delimiter character
        # OPA validates each delimiter with Go's `len()` (byte length), so a
        # multi-byte single character (e.g. "£") is rejected, not just multi-char ones.
        def self.single_delimiter(value, context)
          delimiter = string_arg(value, context)
          bytes = delimiter.bytesize
          return delimiter if bytes == 1

          raise template_error("delimiter must be a single byte", "byte length #{bytes}", context)
        end
        private_class_method :single_delimiter

        # Builds an anchored Ruby pattern: literal characters are escaped, text between
        # the delimiters is kept as a regex section.
        #
        # @return [String]
        # :reek:TooManyStatements
        # :reek:LongParameterList
        # :reek:ControlParameter
        # rubocop:disable Metrics/MethodLength, Metrics/AbcSize
        def self.template_source(template, delim_start, delim_end, context)
          buffer = +"\\A"
          index = 0
          while index < template.length
            char = template[index].to_s
            if char == delim_start
              section_start = index + 1
              close = template.index(delim_end, section_start)
              raise template_error("unbalanced delimiter", "no closing #{delim_end}", context) unless close

              buffer << (template[section_start...close] || "")
              index = close + 1
            else
              # A closing delimiter outside a section is unbalanced (OPA → undefined).
              raise template_error("unbalanced delimiter", "stray #{delim_end}", context) if char == delim_end

              buffer << Regexp.escape(char)
              index += 1
            end
          end
          "#{buffer}\\z"
        end
        # rubocop:enable Metrics/MethodLength, Metrics/AbcSize
        private_class_method :template_source

        # @return [Ruby::Rego::BuiltinArgumentError]
        def self.template_error(message, actual, context)
          Ruby::Rego::BuiltinArgumentError.new(
            message,
            expected: "single-character delimiters and balanced sections",
            actual: actual,
            context: context,
            location: nil
          )
        end
        private_class_method :template_error
      end
    end
  end
end
