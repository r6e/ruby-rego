# frozen_string_literal: true

module Ruby
  module Rego
    module Builtins
      # Built-in string helpers.
      module Strings
        # @param string [Ruby::Rego::Value]
        # @param cutset [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.trim(string, cutset)
          trim_with_cutset(string, cutset, { mode: :both, name: "trim" })
        end

        # @param string [Ruby::Rego::Value]
        # @param cutset [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.trim_left(string, cutset)
          trim_with_cutset(string, cutset, { mode: :left, name: "trim_left" })
        end

        # @param string [Ruby::Rego::Value]
        # @param cutset [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.trim_right(string, cutset)
          trim_with_cutset(string, cutset, { mode: :right, name: "trim_right" })
        end

        # @param string [Ruby::Rego::Value]
        # @return [Ruby::Rego::StringValue]
        def self.trim_space(string)
          StringValue.new(string_value(string, context: "trim_space").strip)
        end

        def self.trim_with_cutset(string, cutset, context)
          StringValue.new(trimmed_text(string, cutset, context))
        end
        private_class_method :trim_with_cutset
      end
    end
  end
end
