# frozen_string_literal: true

require_relative "rego/version"
require_relative "rego/location"
require_relative "rego/errors"
require_relative "rego/token"
require_relative "rego/lexer"
require_relative "rego/ast"
require_relative "rego/parser"
require_relative "rego/value"
require_relative "rego/builtins/base"
require_relative "rego/builtins/registry"
require_relative "rego/builtins/types"
require_relative "rego/builtins/aggregates"
require_relative "rego/builtins/strings"
require_relative "rego/environment"
require_relative "rego/unifier"
require_relative "rego/result"
require_relative "rego/evaluator"

module Ruby
  # Top-level namespace for the Ruby Rego gem.
  module Rego
    # Your code goes here...
  end
end
