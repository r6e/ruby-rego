# Architecture

## Overview

Ruby::Rego is a pure Ruby implementation of the Rego policy language. It follows a compiler-style pipeline: parse source into an AST, compile the AST into indexed structures, and evaluate those structures against input and data.

## Component responsibilities

- Lexer: converts source code into tokens.
- Parser: builds an AST from the token stream.
- AST nodes: model Rego constructs (rules, expressions, references).
- Compiler: validates and indexes rules, produces a CompiledModule.
- CompiledModule: immutable bundle of rules, package path, and dependency graph.
- Evaluator: executes queries or rule groups using the compiled module.
- Environment: stores input, data, local bindings, and builtins.
- Values: wrap Ruby primitives for Rego semantics and undefined handling.
- Builtins: registry of supported functions.
- Unifier: resolves pattern matching and binding logic.
- CLI: validates inputs against policies via the public API.

## Data flow

1. Source -> Lexer -> Tokens
2. Tokens -> Parser -> AST::Module
3. AST -> Compiler -> CompiledModule
4. CompiledModule + input/data -> Evaluator -> Result

The evaluator walks the AST through rule evaluators and expression evaluators, resolving references against the Environment and invoking builtins when needed. Errors bubble up with location metadata to provide actionable diagnostics.

## Extension points

- Builtins: add new functions by extending the builtin registry and adding tests.
- Parser: add new syntax by introducing AST nodes and parser rules.
- Evaluator: support new expressions or keywords by adding evaluators.
- CLI: add new flags or output modes by extending the CLI classes.

## Error handling

Public API calls wrap errors with location information to present a consistent error shape. Internal helpers raise specialized error subclasses to clarify failure sources (lexer, parser, compiler, evaluator, unifier).
