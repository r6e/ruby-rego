# frozen_string_literal: true

module Ruby
  module Rego
    # Parsing helpers for rules and module declarations.
    # :reek:TooManyMethods
    # :reek:DataClump
    # :reek:RepeatedConditional
    # rubocop:disable Metrics/ClassLength
    class Parser
      private

      # :reek:TooManyStatements
      def parse_module
        consume_newlines
        package = parse_package
        imports = [] # @type var imports: Array[AST::Import]
        rules = [] # @type var rules: Array[AST::Rule]

        consume_newlines
        until at_end?
          parse_statement(imports, rules)
          consume_newlines
        end

        AST::Module.new(package: package, imports: imports, rules: rules, location: package.location)
      end

      # :reek:UncommunicativeVariableName
      # :reek:TooManyStatements
      def parse_statement(imports, rules)
        consume_newlines
        return if at_end?

        if match?(TokenType::IMPORT)
          imports << parse_import
        else
          rules << parse_rule
        end
      rescue ParserError => e
        record_error(e)
        synchronize
      end

      def parse_package
        keyword = consume(TokenType::PACKAGE, "Expected package declaration.")
        path = parse_path(IdentifierContext.new(name: "package", allowed_types: PACKAGE_PATH_TOKEN_TYPES))
        AST::Package.new(path: path, location: keyword.location)
      end

      def parse_import
        keyword = consume(TokenType::IMPORT, "Expected import declaration.")
        path = parse_path(IdentifierContext.new(name: "import", allowed_types: IMPORT_PATH_TOKEN_TYPES))
        alias_name = parse_import_alias

        AST::Import.new(path: path, alias_name: alias_name, location: keyword.location)
      end

      def parse_import_alias
        return nil unless match?(TokenType::AS)

        advance
        parse_identifier(IdentifierContext.new(name: "import alias", allowed_types: PACKAGE_PATH_TOKEN_TYPES))
      end

      # :reek:TooManyStatements
      def parse_rule
        default_token = consume_default_keyword
        name_token = current_token
        name, head_segments = parse_rule_name_path
        head = parse_rule_head(name, name_token)
        head = apply_rule_head_path(head, head_segments, name_token)
        head = mark_default_head(head) if default_token
        definition = parse_rule_definition(default_token, head)
        validate_rule_definition(default_token, head, definition)

        build_rule_node(name: name, head: head, name_token: name_token, definition: definition)
      end

      def consume_default_keyword
        match?(TokenType::DEFAULT) ? advance : nil
      end

      def parse_rule_name_path
        context = IdentifierContext.new(name: "rule", allowed_types: PACKAGE_PATH_TOKEN_TYPES)
        name = parse_identifier(context)
        [name, parse_rule_head_segments(context)]
      end

      def parse_rule_head_segments(context)
        segments = [] # @type var segments: Array[AST::expression]
        loop do
          segment = parse_rule_head_segment(context, segments)
          break unless segment

          segments << segment
        end
        segments
      end

      def parse_rule_head_segment(context, segments)
        return parse_dot_rule_head_segment(context) if match?(TokenType::DOT)
        return parse_bracket_rule_head_segment(segments) if match?(TokenType::LBRACKET)

        nil
      end

      def parse_dot_rule_head_segment(context)
        advance
        segment_token = current_token
        segment = parse_identifier(context)
        AST::StringLiteral.new(value: segment, location: segment_token.location)
      end

      def parse_bracket_rule_head_segment(segments)
        return parse_rule_head_path_segment if bracket_string_segment?
        return parse_rule_head_path_segment if segments.any?

        return nil unless bracket_expression_followed_by_path?

        parse_rule_head_path_segment
      end

      # :reek:UtilityFunction
      def mark_default_head(head)
        head.merge(default: true)
      end

      # :reek:NilCheck
      # :reek:ControlParameter
      def parse_default_value(default_token, head)
        return nil unless default_token

        default_value = head[:value]
        parse_error("Expected default rule value.") if default_value.nil?
        default_value
      end

      # :reek:ControlParameter
      def parse_non_default_body(default_token)
        return nil if default_token
        return nil unless match?(TokenType::IF, TokenType::LBRACE)

        parse_rule_body
      end

      def parse_rule_definition(default_token, head)
        default_value = parse_default_value(default_token, head)
        body = parse_non_default_body(default_token)
        else_clause = parse_else_clause_for_definition(default_token)

        {
          default_value: default_value,
          body: body,
          else_clause: else_clause
        }
      end

      # :reek:ControlParameter
      def parse_else_clause_for_definition(default_token)
        consume_newlines
        parse_error("Default rules cannot have else clauses.") if default_token && match?(TokenType::ELSE)
        parse_else_clause_if_present
      end

      # :reek:FeatureEnvy
      # :reek:ControlParameter
      def validate_rule_definition(default_token, head, definition)
        return if default_token
        return unless head[:type] == :complete
        return if head[:value] || definition[:body]

        parse_error("Expected rule body or value.")
      end

      def parse_else_clause_if_present
        return nil unless match?(TokenType::ELSE)

        parse_else_clause
      end

      # :reek:UtilityFunction
      # :reek:LongParameterList
      def build_rule_node(name:, head:, name_token:, definition:)
        AST::Rule.new(
          name: name,
          head: head,
          body: definition[:body],
          default_value: definition[:default_value],
          else_clause: definition[:else_clause],
          location: name_token.location
        )
      end

      def parse_rule_head(name, name_token)
        return parse_contains_rule_head(name, name_token) if match?(TokenType::CONTAINS)
        return parse_function_rule_head(name, name_token) if match?(TokenType::LPAREN)
        return parse_bracket_rule_head(name, name_token) if match?(TokenType::LBRACKET)

        build_rule_head(:complete, name, name_token, value: parse_rule_value)
      end

      def parse_contains_rule_head(name, name_token)
        advance
        term = parse_expression
        build_rule_head(:partial_set, name, name_token, term: term)
      end

      def parse_function_rule_head(name, name_token)
        args = parse_rule_head_args
        value = parse_rule_value
        build_rule_head(:function, name, name_token, args: args, value: value)
      end

      def parse_bracket_rule_head(name, name_token)
        key = parse_rule_head_key
        return parse_partial_object_rule_head(name, name_token, key) if match?(TokenType::ASSIGN, TokenType::UNIFY)

        build_rule_head(:partial_set, name, name_token, term: key)
      end

      def parse_partial_object_rule_head(name, name_token, key)
        advance
        value = parse_expression
        build_rule_head(:partial_object, name, name_token, key: key, value: value)
      end

      # :reek:UtilityFunction
      # :reek:LongParameterList
      def build_rule_head(type, name, name_token, **attrs)
        { type: type, name: name, location: name_token.location }.merge(attrs)
      end

      def apply_rule_head_path(head, segments, name_token)
        return head if segments.empty?
        return nested_rule_head(head, segments, name_token) if head[:type] == :complete

        parse_error("Rule head references require complete rule definitions.")
      end

      # :reek:UtilityFunction
      def nested_rule_head(head, segments, name_token)
        return rule_head_path_builder(head, segments, name_token).call if segments.any?

        raise ParserError.from_position(
          "Expected rule head segments.",
          position: rule_head_location(name_token),
          context: nil
        )
      end

      def rule_head_path_builder(head, segments, name_token)
        RuleHeadPathBuilder.new(head: head, segments: segments, location: rule_head_location(name_token))
      end

      def rule_head_location(name_token)
        name_token.location || current_token.location || Location.new(
          line: 1,
          column: 1,
          offset: nil,
          length: nil
        )
      end

      def bracket_expression_followed_by_path?
        closing_index = matching_bracket_index(current_index)
        return false unless closing_index

        next_token = next_non_newline_token(closing_index + 1)
        return false unless next_token

        [TokenType::DOT, TokenType::LBRACKET].include?(next_token.type)
      end

      def matching_bracket_index(start_index)
        bracket_matcher.matching_index(start_index)
      end

      def next_non_newline_token(start_index)
        index = start_index
        loop do
          token = safe_token_at(index)
          return token unless [TokenType::NEWLINE, TokenType::COMMENT].include?(token.type)

          index += 1
        end
      end

      def bracket_matcher
        @bracket_matcher ||= BracketMatcher.new(token_provider: ->(index) { safe_token_at(index) })
      end

      # Builds nested object values for rule head segments.
      class RuleHeadPathBuilder
        # @param head [Hash]
        # @param segments [Array<AST::expression>]
        # @param location [Location]
        def initialize(head:, segments:, location:)
          @head = head
          @segments = segments
          @location = location
        end

        # @return [Hash]
        def call
          key_segment, *remaining = segments
          return head unless key_segment

          value_node = head[:value] || AST::BooleanLiteral.new(value: true, location: location)
          value_node = build_nested_value(remaining, value_node)

          head.merge(
            type: :partial_object,
            key: normalize(key_segment),
            value: value_node,
            nested: remaining.any?
          )
        end

        private

        attr_reader :head, :segments, :location

        def build_nested_value(segments, value_node)
          segments.reverse_each do |segment|
            key_node = normalize(segment) # @type var key_node: AST::expression
            value_node = AST::ObjectLiteral.new(pairs: [[key_node, value_node]], location: location)
          end
          value_node
        end

        # :reek:FeatureEnvy
        def normalize(segment)
          return segment if segment.is_a?(AST::Base)

          AST::StringLiteral.new(value: segment.to_s, location: location)
        end
      end

      # Finds matching closing brackets for rule head path segments.
      class BracketMatcher
        BRACKET_DEPTH_DELTA = {
          TokenType::LBRACKET => 1,
          TokenType::RBRACKET => -1
        }.freeze

        # @param token_provider [#call]
        def initialize(token_provider:)
          @token_provider = token_provider
        end

        # @param start_index [Integer]
        # @return [Integer, nil]
        # :reek:FeatureEnvy
        def matching_index(start_index)
          depth = 0

          loop do
            token_type = token_provider.call(start_index).type
            return nil if token_type == TokenType::EOF

            depth += BRACKET_DEPTH_DELTA.fetch(token_type, 0)
            return start_index if token_type == TokenType::RBRACKET && depth.zero?

            start_index += 1
          end
        end

        private

        attr_reader :token_provider
      end

      def parse_rule_head_path_segment
        consume(TokenType::LBRACKET, "Expected '[' after rule name.")
        consume_newlines
        segment = parse_expression
        consume_newlines
        consume(TokenType::RBRACKET, "Expected ']' after rule path segment.")
        segment
      end

      # :reek:TooManyStatements
      def parse_rule_head_args
        parse_parenthesized_expression_list(
          open_message: "Expected '(' after rule name.",
          close_message: "Expected ')' after rule arguments."
        )
      end

      # :reek:TooManyStatements
      def parse_rule_head_key
        consume(TokenType::LBRACKET, "Expected '[' after rule name.")
        consume_newlines
        key = parse_expression
        consume_newlines
        consume(TokenType::RBRACKET, "Expected ']' after rule key.")
        key
      end

      def parse_rule_value
        return nil unless match?(TokenType::ASSIGN, TokenType::UNIFY)

        advance
        parse_expression
      end

      def parse_rule_body
        advance if match?(TokenType::IF)
        return parse_braced_rule_body if match?(TokenType::LBRACE)

        parse_query(TokenType::ELSE, TokenType::EOF, TokenType::NEWLINE, newline_delimiter: false)
      end

      # :reek:TooManyStatements
      def parse_braced_rule_body
        advance
        consume_newlines
        return parse_empty_rule_body if rbrace_token?

        body = parse_query(TokenType::RBRACE, newline_delimiter: true)
        consume(TokenType::RBRACE, "Expected '}' after rule body.")
        body
      end

      def parse_empty_rule_body
        advance
        []
      end

      def parse_else_clause
        keyword = consume(TokenType::ELSE, "Expected 'else' clause.")
        value = nil
        value = parse_rule_value if match?(TokenType::ASSIGN, TokenType::UNIFY)
        body = parse_rule_body if match?(TokenType::IF, TokenType::LBRACE)
        else_clause = parse_else_clause_if_present

        { value: value, body: body, location: keyword.location, else_clause: else_clause }
      end
    end
    # rubocop:enable Metrics/ClassLength
  end
end
