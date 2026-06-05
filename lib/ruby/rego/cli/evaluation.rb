# frozen_string_literal: true

require "ruby/rego"

# Policy evaluation and outcome construction for rego-validate.
module RegoValidate
  # Compiles and evaluates policies with a resolved query.
  class PolicyEvaluator
    # Create a policy evaluator.
    #
    # @param policy_source [String]
    # @param input [Object]
    # @param query [String, nil]
    def initialize(policy_source, input, query, profiler: nil)
      @policy_source = policy_source
      @input = input
      @query = query
      @profiler = profiler
    end

    # Compile and evaluate the policy using the resolved query.
    #
    # @return [EvaluationResult]
    def evaluate
      compiled_module = measure("compile") { Ruby::Rego.compile(policy_source) }
      query_path = resolve_query(compiled_module)
      return EvaluationResult.new(error_message: "No default validation rule found. Provide --query.") unless query_path

      build_evaluation(compiled_module, query_path)
    ensure
      profiler&.report
    end

    private

    attr_reader :policy_source, :input, :query, :profiler

    def resolve_query(compiled_module)
      query || DefaultQueryResolver.new(compiled_module).resolve
    end

    def build_evaluation(compiled_module, query_path)
      result = measure("evaluate") { evaluate_compiled(compiled_module, query_path) }
      outcome = OutcomeBuilder.new(result, query_path).build
      EvaluationResult.new(outcome: outcome)
    end

    def evaluate_compiled(compiled_module, query_path)
      Ruby::Rego::Evaluator.new(compiled_module, input: input, data: nil).evaluate(query_path)
    rescue Ruby::Rego::Error
      raise
    rescue StandardError => e
      raise Ruby::Rego::Error.new("Rego evaluation failed: #{e.message}", location: nil), cause: e
    end

    def measure(label, &)
      return yield unless profiler

      profiler.measure(label, &)
    end
  end

  # Builds a normalized outcome payload from evaluation results.
  class OutcomeBuilder
    # Create an outcome builder.
    #
    # @param result [Ruby::Rego::Result, nil]
    # @param query [String]
    def initialize(result, query)
      @result = result
      @query = query
    end

    # Build the normalized outcome.
    #
    # @return [Outcome]
    def build
      return undefined_outcome unless result
      return undefined_outcome if result.undefined?

      build_defined_outcome
    end

    private

    attr_reader :result, :query

    def build_defined_outcome
      value = defined_result.value.to_ruby
      errors = errors_for(value)
      Outcome.new(success: errors.empty?, value: value, errors: errors)
    end

    def errors_for(value)
      errors = errors_from_value(value)
      result_errors = defined_result.errors
      errors.concat(result_errors.map(&:to_s)) unless result_errors.empty?
      errors
    end

    def defined_result
      result || raise("Expected defined result")
    end

    def undefined_outcome
      Outcome.new(success: false, value: nil, errors: [format_rule_error("undefined")])
    end

    def errors_from_value(value)
      return [] if value == true

      errors_for_non_true(value)
    end

    def errors_for_non_true(value)
      scalar = scalar_error(value)
      return scalar unless value
      return collection_errors(value) if value.is_a?(Array) || value.is_a?(Set)
      return hash_errors(value) if value.is_a?(Hash)

      scalar
    end

    def scalar_error(value)
      [format_rule_error(value)]
    end

    def collection_errors(value)
      value.to_a.map { |item| format_rule_error(item) }
    end

    def hash_errors(value)
      return [] if value.empty?

      [format_rule_error(value)]
    end

    def format_rule_error(value)
      "Rule '#{rule_name}' returned: #{value.inspect}"
    end

    def rule_name
      @rule_name ||= query.to_s.split(".").last
    end
  end
end
