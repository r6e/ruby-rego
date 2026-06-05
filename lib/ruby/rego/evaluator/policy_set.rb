# frozen_string_literal: true

module Ruby
  module Rego
    # Evaluates compiled Rego modules against input and data.
    class Evaluator
      # Policy-set (multi-module) evaluation: module contexts, package-conflict detection, and subtree assignment.

      private

      def evaluate_policy_set(query)
        return evaluate_policy_set_query(query) if query

        value = evaluate_policy_set_rules
        ResultBuilder.new(value, nil).build
      end

      def evaluate_policy_set_query(query)
        context = context_for_query(query)
        return nil unless context

        evaluator = context.expression_evaluator
        node = QueryNodeBuilder.new(query).build
        bindings = evaluator.eval_with_unification(node, environment).first || {}
        value = evaluator.evaluate(node)
        return nil if value.is_a?(UndefinedValue)

        ResultBuilder.new(value, bindings).build
      end

      def context_for_query(query)
        keys = query.to_s.split(".")
        keys = keys[1..] || [] if keys.first == "data"
        mod = policy_set.module_for(keys)
        return context_by_module(mod) if mod

        # No module owns the query path: fall back to the first context. This
        # correctly handles non-data queries (input refs, literal expressions),
        # which evaluate against the shared environment, and unowned data paths,
        # which resolve to undefined regardless of which context is used.
        module_contexts.first
      end

      def context_by_module(mod)
        module_contexts.find { |context| context.compiled_module.equal?(mod) }
      end

      def evaluate_policy_set_rules
        tree = {} # @type var tree: Hash[String, untyped]
        module_contexts.each do |context|
          rules_value = evaluate_module_rules(context)
          next if rules_value.empty?

          assign_package_subtree(tree, context.compiled_module.package_path, rules_value)
        end
        Value.from_ruby(tree)
      end

      # Reject any rule whose full path (package path + rule name) is a prefix of,
      # or equal to, another module's package path. Such a path cannot be both a
      # rule value and a package namespace, matching OPA's conflict semantics. The
      # check is order- and value-shape-independent, unlike a per-node assembly guard.
      def detect_package_rule_conflicts
        package_paths = module_contexts.map { |context| context.compiled_module.package_path }
        module_contexts.each do |context|
          raise_conflicts_for_module(context, package_paths)
        end
      end

      def raise_conflicts_for_module(context, package_paths)
        package_path = context.compiled_module.package_path
        context.compiled_module.rule_names.each do |rule_name|
          rule_path = package_path + [rule_name]
          conflicting = conflicting_package(rule_path, package_paths)
          raise_package_rule_conflict(rule_path, conflicting) if conflicting
        end
      end

      def conflicting_package(rule_path, package_paths)
        package_paths.find { |other| package_prefix?(rule_path, other) }
      end

      def raise_package_rule_conflict(rule_path, conflicting)
        raise EvaluationError.new(
          "Rule #{rule_path.join(".")} conflicts with package #{conflicting.join(".")}",
          rule: nil,
          location: nil
        )
      end

      # True when `prefix` is a (non-strict) prefix of `path` — i.e. the rule path
      # is used as, or as an ancestor of, a package namespace.
      def package_prefix?(prefix, path)
        path.length >= prefix.length && path[0, prefix.length] == prefix
      end

      def evaluate_module_rules(context)
        evaluator = context.rule_evaluator
        mod = context.compiled_module
        results = {} # @type var results: Hash[String, untyped]
        mod.rules_by_name.each do |name, rules|
          value = evaluator.evaluate_group(rules)
          results[name] = value.to_ruby unless value.is_a?(UndefinedValue)
        end
        results
      end

      def assign_package_subtree(tree, package_path, rules_value)
        node = tree # @type var node: untyped
        parent_segments = package_path[0...-1] || [] # @type var parent_segments: Array[String]
        empty = {} # @type var empty: Hash[String, untyped]
        parent_segments.each do |segment|
          node = (node[segment] ||= empty.dup)
        end
        last = package_path.last
        existing = node[last]
        node[last] = existing.is_a?(Hash) ? existing.merge(rules_value) : rules_value
      end
    end
  end
end
