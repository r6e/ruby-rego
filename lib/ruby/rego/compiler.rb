# frozen_string_literal: true

require_relative "ast"
require_relative "compiled_module"
require_relative "compiled_policy_set"
require_relative "call_name"
require_relative "errors"
require_relative "environment"
require_relative "builtins/registry"
require_relative "evaluator/variable_collector"
require_relative "lexer"
require_relative "parser"
require_relative "compiler/rule_index"
require_relative "compiler/safety"
require_relative "compiler/dependencies"

module Ruby
  # Rego compilation helpers.
  module Rego
    # Compiles AST modules into indexed structures for evaluation.
    class Compiler # rubocop:disable Metrics/ClassLength
      # Create a compiler instance.
      #
      # @param builtin_registry [Builtins::BuiltinRegistry] registry for builtin lookup
      # @param default_rule_validator [DefaultRuleValidator, nil] override validator
      def initialize(builtin_registry: Builtins::BuiltinRegistry.instance, default_rule_validator: nil)
        @builtin_registry = builtin_registry
        @default_rule_validator = default_rule_validator
      end

      # Compile an AST module into a compiled module.
      #
      # @param ast_module [AST::Module] parsed module
      # @return [CompiledModule] compiled module
      def compile(ast_module)
        rules_by_name = compile_rules(ast_module)
        package_path = ast_module.package.path
        dependency_graph = dependency_graph_builder.build(rules_by_name, package_path)
        artifacts = CompilationArtifacts.new(
          rules_by_name: rules_by_name,
          package_path: package_path,
          dependency_graph: dependency_graph
        )
        CompiledModuleBuilder.build(ast_module, artifacts)
      end

      # Compile a named set of module sources into a policy set.
      #
      # @param modules [Hash{String => String}] map of name => Rego source
      # @return [CompiledPolicySet] compiled policy set
      def compile_set(modules)
        ast_modules = parse_named_modules(modules)
        merged = merge_modules_by_package(ast_modules)
        CompiledPolicySet.new(merged.map { |ast_module| compile(ast_module) })
      end

      # Index rules by name.
      #
      # @param rules [Array<AST::Rule>] rules to index
      # @return [Hash{String => Array<AST::Rule>}] rules indexed by name
      def index_rules(rules)
        rule_indexer.index(rules)
      end

      # Validate a rule set for conflicts.
      #
      # @param rules [Array<AST::Rule>, Hash{String => Array<AST::Rule>}] rules to check
      # @return [void]
      def check_conflicts(rules)
        conflict_checker.check(rules)
      end

      # Validate a rule for safety (unbound variables).
      #
      # @param rule [AST::Rule] rule to check
      # @return [void]
      def check_safety(rule)
        safety_checker.check_rule(rule)
      end

      private

      # :reek:TooManyStatements
      def compile_rules(ast_module)
        rule_names = (rules_by_name = index_rules(ast_module.rules)).keys
        imports = ast_module.imports
        validate_import_aliases(imports, rule_names)
        check_conflicts(rules_by_name)
        validate_function_name_conflicts(rules_by_name)
        safe_names = safe_names_for_imports(imports) | rule_names
        safety_checker.check_rules(rules_by_name, safe_names: safe_names)
        default_rule_validator.check(rules_by_name)
        rules_by_name
      end

      def parse_named_modules(modules)
        modules.map do |name, source|
          ErrorHandling.wrap(name.to_s) { parse_source(source) }
        end
      end

      def parse_source(source)
        tokens = Lexer.new(source).tokenize
        Parser.new(tokens).parse
      end

      def merge_modules_by_package(ast_modules)
        grouped = ast_modules.group_by { |ast_module| ast_module.package.path }
        grouped.map do |_path, group|
          next group.first if group.length == 1

          merge_group(group)
        end
      end

      def merge_group(group)
        first = group.first
        AST::Module.new(
          package: first.package,
          imports: merge_imports(group),
          rules: group.flat_map(&:rules),
          location: first.location
        )
      end

      def merge_imports(group)
        group.flat_map(&:imports).uniq { |import| [import.path, import.alias_name] }
      end

      def rule_indexer
        @rule_indexer ||= RuleIndexer
      end

      def conflict_checker
        @conflict_checker ||= ConflictChecker.new
      end

      def safety_checker
        @safety_checker ||= SafetyChecker.new
      end

      def safe_names_for_imports(imports)
        base = Environment::RESERVED_NAMES + ["_"]
        import_names = Array(imports).filter_map { |import| import_alias_name(import) }
        (base + import_names).uniq
      end

      def validate_import_aliases(imports, rule_names)
        seen = {} # @type var seen: Hash[String, true]
        Array(imports).each { |import| validate_import_alias(import, seen, rule_names) }
      end

      # rubocop:disable Metrics/MethodLength
      # :reek:TooManyStatements
      def validate_import_alias(import, seen, rule_names)
        name = import_alias_name(import)
        return unless name

        location = import.location

        if reserved_import_alias?(name, import)
          raise CompilationError.new(
            "Import alias conflicts with reserved name: #{name}",
            location: location
          )
        end

        if rule_names.include?(name)
          raise CompilationError.new(
            "Import alias conflicts with rule name: #{name}",
            location: location
          )
        end

        if seen.key?(name)
          raise CompilationError.new(
            "Duplicate import alias: #{name}",
            location: location
          )
        end

        seen[name] = true
      end
      # rubocop:enable Metrics/MethodLength

      # :reek:UtilityFunction
      def reserved_import_alias?(name, import)
        reserved_names = Environment::RESERVED_NAMES + ["_"]
        return false unless reserved_names.include?(name)

        return false if !import.alias_name && import_path_exact?(import, name)

        true
      end

      # :reek:UtilityFunction
      def import_path_exact?(import, name)
        path = import.path
        return path == [name] if path.is_a?(Array)

        path.to_s == name
      end

      # :reek:TooManyStatements
      # :reek:UtilityFunction
      def import_alias_name(import)
        alias_name = import.alias_name
        return alias_name.to_s if alias_name

        path = import.path
        return path.last.to_s if path.is_a?(Array) && !path.empty?
        return path.to_s.split(".").last if path

        nil
      end

      def default_rule_validator
        @default_rule_validator ||= DefaultRuleValidator.new(builtin_registry: builtin_registry)
      end

      def dependency_graph_builder
        @dependency_graph_builder ||= DependencyGraphBuilder.new
      end

      def validate_function_name_conflicts(rules_by_name)
        rules_by_name.each do |name, rules|
          rule = conflicting_function_rule(name, rules)
          next unless rule

          raise CompilationError.new(
            "Function name conflicts with builtin: #{name}",
            location: rule.location
          )
        end
      end

      def conflicting_function_rule(name, rules)
        return nil unless builtin_registry.registered?(name)

        rules.find(&:function?)
      end

      attr_reader :builtin_registry
    end

    # Bundles compiled module inputs.
    CompilationArtifacts = Struct.new(
      :rules_by_name,
      :package_path,
      :dependency_graph
    )
    private_constant :CompilationArtifacts
  end
end
