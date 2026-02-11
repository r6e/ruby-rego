# frozen_string_literal: true

require_relative "rego/version"
require_relative "rego/location"
require_relative "rego/errors"
require_relative "rego/error_handling"
require_relative "rego/token"
require_relative "rego/lexer"
require_relative "rego/ast"
require_relative "rego/call_name"
require_relative "rego/parser"
require_relative "rego/value"
require_relative "rego/builtins/base"
require_relative "rego/builtins/registry"
require_relative "rego/builtins/types"
require_relative "rego/builtins/aggregates"
require_relative "rego/builtins/strings"
require_relative "rego/builtins/collections"
require_relative "rego/builtins/comparisons"
require_relative "rego/memoization"
require_relative "rego/environment"
require_relative "rego/environment_pool"
require_relative "rego/compiled_module"
require_relative "rego/compiler"
require_relative "rego/with_modifiers/with_modifier"
require_relative "rego/unifier"
require_relative "rego/result"
require_relative "rego/evaluator"
require_relative "rego/policy"

module Ruby
  # Top-level namespace for the Ruby Rego gem.
  module Rego
    class << self
      # Parse Rego source into an AST module.
      #
      # @param source [String] Rego source code
      # @return [AST::Module] parsed AST module
      def parse(source)
        ErrorHandling.wrap("parsing") do
          tokens = Lexer.new(source).tokenize
          Parser.new(tokens).parse
        end
      end

      # Compile Rego source into an immutable compiled module.
      #
      # @param source [String] Rego source code
      # @return [CompiledModule] compiled and indexed module
      def compile(source)
        ErrorHandling.wrap("compilation") do
          Compiler.new.compile(parse(source))
        end
      end

      # Evaluate Rego source against input and data.
      #
      # @param source [String] Rego source code
      # @param input [Object] input document
      # @param data [Object] data document
      # @param query [Object, nil] optional query path
      # @return [Result] evaluation result
      # :reek:LongParameterList
      def evaluate(source, input: {}, data: {}, query: nil)
        compiled_module = compile(source)
        ErrorHandling.wrap("evaluation") do
          Evaluator.new(compiled_module, input: input, data: data).evaluate(query)
        end
      end
    end
  end
end
