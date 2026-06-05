# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- JSON path built-ins: `json.filter` and `json.remove`, matching OPA. Both take an object
  document and an array or set of paths; each path is a `/`-separated string (JSON-pointer
  escaped: `~1` is `/`, `~0` is `~`, with a leading run of slashes stripped before splitting
  so `/a/b` equals `a/b`) or an array of literal segments, and a numeric string segment
  indexes into an array. `json.filter` keeps only the listed paths (a terminal path keeps
  the whole subtree, a path descending past a scalar keeps the scalar, a non-matching child
  becomes an empty container); `json.remove` drops the listed paths (removing array elements
  reindexes, and multiple indices under one array are removed against their original
  positions). A non-object document, a paths argument that is neither an array nor a set, or
  a path element that is neither a string nor an array yields undefined. Pure structural
  rewrites of the parsed value (linear in document size); hand-rolled, no new dependency.

- Encoding built-ins: `base64url.encode_no_pad` (base64url without `=` padding),
  `urlquery.encode_object`, and `urlquery.decode_object`, matching OPA. `encode_object`
  encodes an object as a query string (keys sorted; a string value emits one pair, an
  array value one pair per element keeping order, a set value sorted and de-duplicated;
  keys and values are escaped); a non-object, non-string key, or value that is not a string
  or string array/set yields undefined. `decode_object` parses a query string into an
  object mapping each key to its array of values; a malformed percent-escape (in any key or
  value) yields undefined. Reuses the existing `urlquery.encode`/`decode` escaping
  primitives; no new dependency.

- SemVer built-ins: `semver.is_valid` and `semver.compare`, matching OPA (which vendors
  coreos/go-semver). A version is `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]`; the parser is
  lenient like OPA's (accepts a leading lowercase `v` and leading zeros), and each numeric
  component must fit in a signed 64-bit integer. `is_valid` is total over runtime values (a
  non-string yields `false`); `compare(a, b)` returns `-1`/`0`/`1` (build metadata ignored,
  SemVer §11 precedence) and yields undefined for a non-string or invalid version.
  Hand-rolled (no new dependency). One intentional divergence: OPA's `semver.compare`
  infinite-loops when two numeric prerelease identifiers are equal in value but differ
  textually via leading zeros (e.g. `1.0.0-01` vs `1.0.0-1`) — an upstream coreos/go-semver
  bug; this implementation compares them numerically (equal), terminates, and returns the
  correct result instead of hanging.

- Net/CIDR built-ins: `net.cidr_contains`, `net.cidr_intersects`, and `net.cidr_is_valid`,
  matching OPA. Backed by Ruby's `IPAddr` (IPv4 and IPv6). A cidr requires a prefix length
  (a bare IP is not a cidr); host bits beyond the prefix are masked. `cidr_contains(cidr,
  ip_or_cidr)` and `cidr_intersects(cidr, cidr)` return a boolean and yield undefined for a
  non-string or invalid argument (and false across address families). `cidr_is_valid` is
  total over runtime values — a non-string or non-CIDR string yields `false` (not
  undefined), like `regex.is_valid`. Parsing is reconciled with OPA/Go: a dotted-decimal
  netmask, a scoped (`%zone`) or bracketed (`[..]`) address is rejected, and a leading-zero
  prefix (`/08`) is accepted as `/8`. IPv4-mapped IPv6 addresses are normalised to their
  native IPv4 form to match OPA. One intentional divergence: an IPv4-mapped IPv6 CIDR with
  a prefix in 80..95 (which cuts through the `::ffff:` marker) is a degenerate input where
  OPA inherits golang/go#51906 and `cidr_contains` is non-reflexive; the gem keeps the
  reflexive result instead of reproducing the upstream Go inconsistency. Adds `ipaddr` as a
  runtime dependency.

- Crypto built-ins: `crypto.hmac.md5`, `crypto.hmac.sha1`, `crypto.hmac.sha256`,
  `crypto.hmac.sha512`, and `crypto.hmac.equal`, matching OPA. The HMAC digests take
  `(message, key)` (OPA's argument order, the reverse of Ruby's
  `OpenSSL::HMAC.hexdigest`) and return a lowercase hex digest; a non-string message or
  key yields undefined. `crypto.hmac.equal` is a constant-time comparison
  (`OpenSSL.secure_compare`) returning a boolean — `false` for unequal-length inputs
  (matching Go's `hmac.Equal`), undefined for a non-string argument. Adds `openssl` as a
  runtime dependency.

- Regex built-in: `regex.replace`, matching OPA. The replacement value uses Go's `Expand`
  template syntax (`$1`/`${name}` submatch references, `$0` whole match, `$$` literal `$`;
  unknown or out-of-range references — including a multi-digit leading-zero reference like
  `$01` — expand to the empty string), and a backslash is a literal. Go's `(?P<name>...)`
  named-group syntax — and RE2's `(?<name>...)` synonym — are supported across the regex
  built-ins: named groups are rewritten to
  plain captures and `${name}` references resolve through a name→index map, so named and
  unnamed groups share one RE2-style numbering space (mixed groups and numbered references
  work); names must be RE2 identifiers for `${name}` resolution. A non-identifier (e.g.
  Unicode) name is rejected in the `(?P<…>` form (matching RE2 → undefined), but the
  `(?<…>` form is Onigmo-native and accepts such a name per the superset policy below, so
  the two synonyms diverge for non-identifier names. The
  translation skips `(?P<`/`(?<` inside a character class or after a backslash, leaves
  lookbehind `(?<=`/`(?<!` untranslated, and scans each
  group name in linear time so an adversarial pattern (many `(?P<` with no closing `>`)
  cannot cause quadratic preprocessing. As anti-DoS guards, a pattern or replacement
  template longer than ~1M bytes is rejected up front (each is split into a character
  array before processing — an uninterruptible operation no timeout can bound); the regex timeout
  (`RUBY_REGO_REGEX_TIMEOUT`, default 1s) now also applies as an aggregate deadline across
  the whole match loop (so a cheap-per-match pattern over a long subject — O(n) scans per
  match — yields undefined instead of running quadratically; this bounds `regex.match`,
  `regex.find_n`, `regex.split`, and `regex.replace`), and a `regex.replace` additionally
  yields undefined when either its expanded output would exceed
  ~32M characters or its total template-segment expansions (matches × template segments)
  would exceed ~32M — the latter bounds CPU even when references resolve to empty and emit
  no output, which the output cap alone does not catch. An invalid-encoding string argument
  to a regex built-in now yields undefined rather than raising. `regex.is_valid` is now
  total over runtime values like OPA's: a non-string argument yields `false` (not undefined,
  unlike the other regex built-ins), and an over-length pattern yields `false`.

- Glob built-ins: `glob.match` (wildcards `*`/`**`/`?`, character classes `[...]`/`[!...]`,
  brace alternation `{a,b}` with nesting, escaping, and OPA delimiter semantics — a null
  delimiters argument means "no delimiters", an empty array defaults to `["."]`) and
  `glob.quote_meta`. Matching is by Unicode codepoint; malformed patterns yield undefined.
  Patterns are compiled to an anchored Ruby Regexp under the regex timeout guard. This
  implements correct glob semantics and intentionally does **not** reproduce known bugs in
  OPA's matcher (gobwas/glob): character classes use standard semantics (multiple ranges
  and ranges mixed with literals, e.g. `[A-Za-z]` and `[a0-9]`) rather than gobwas's
  restrictive single-range grammar (gobwas #47), `?` matches non-ASCII characters
  consistently by codepoint even mid-pattern where OPA's `?` still fails on non-ASCII in a
  sequence (gobwas #41), `?`/`[!...]` require exactly one character instead of also
  matching the empty string, and degenerate forms OPA leniently accepts (an unterminated
  `{a,b`, an empty `{}`, and a trailing or lone backslash) yield undefined. Outside these
  corrections, well-formed patterns behave identically to OPA. To stay bounded on
  untrusted input,
  patterns with more than 65,536 delimiters, brace nesting deeper than 100, or a compiled
  regex source over 1 MB yield undefined (DoS guards, analogous to the `numbers.range`
  and `bits.lsh` caps).
- Bitwise built-ins: `bits.and`, `bits.or`, `bits.xor`, `bits.negate`, `bits.lsh`,
  and `bits.rsh`, matching OPA (two's-complement infinite precision; integer-valued
  floats accepted, non-integers and negative shift counts yield undefined). A left
  shift whose result would exceed 2^25 bits (~4 MB) yields undefined rather than
  exhausting memory — a deliberate DoS guard, the only divergence from OPA, affecting
  only `bits.lsh`. Parsing now accepts `and`/`or` as reference segments after a dot so
  `bits.and` / `bits.or` are callable from Rego source.
- String built-ins: `strings.replace_n` (modeled on Go's `strings.Replacer`: keys
  applied in ascending sort order, single pass, replaced text not rescanned,
  earliest-sorted key wins on overlap), and `strings.any_prefix_match` /
  `strings.any_suffix_match` (each argument may be a string, array, or set of strings),
  all matching OPA. `strings.replace_n` scans by Unicode codepoint rather than byte, so
  an empty ("") key against multibyte text inserts only at codepoint boundaries
  (keeping valid UTF-8) instead of OPA's byte-level insertion — the only deviation.
- Crypto built-ins: `crypto.md5`, `crypto.sha1`, and `crypto.sha256` (hex digests of
  the input string's bytes; values from JSON/Rego input are UTF-8, matching OPA). Adds
  `digest` as a runtime dependency.
- String built-ins: `replace` (literal, non-overlapping), `trim_prefix`, `trim_suffix`,
  `strings.reverse`, `strings.count`, and `indexof_n`, matching OPA semantics
  (`indexof_n` is undefined for an empty search).
- Object built-ins: `object.union` (deep merge, second operand wins), `object.union_n`,
  and `object.filter`, matching OPA semantics. `object.filter`/`object.remove` now also
  accept an object as the keys collection (using its keys).
- Encoding built-ins: `json.marshal` (sorted keys, sets as sorted arrays,
  Go-style HTML escaping), `json.unmarshal`, `json.is_valid`, `base64`
  encode/decode/is_valid, `base64url` encode/decode, `hex` encode/decode, and
  `urlquery` encode/decode, matching OPA semantics. Invalid decoder input yields
  an undefined result; non-finite numbers and JSON nested beyond Ruby's default
  depth (a DoS safeguard) also yield undefined rather than raising. Adds `base64`,
  `cgi`, and `json` as runtime dependencies.
- Regex built-ins: `regex.match`, `regex.is_valid`, `regex.split`, and
  `regex.find_n`. `regex.split` matches Go's trailing/zero-width/empty-input
  semantics; invalid patterns yield an undefined result. Patterns compile with
  Ruby's regex engine (Onigmo) rather than Go's RE2, so RE2-incompatible
  constructs (lookahead, backreferences) are treated as valid. A per-match
  timeout (RUBY_REGO_REGEX_TIMEOUT, default 1s) yields an undefined result
  instead of hanging on pathological backtracking.
- Numeric built-ins: `abs`, `round`, `ceil`, `floor`, and `numbers.range`,
  matching OPA semantics (round half away from zero; `numbers.range` accepts
  integer-valued bounds and is undefined for a non-integer bound). Non-finite
  inputs and ranges larger than 1,000,000 elements yield an undefined result
  rather than crashing or exhausting memory.
- Multi-module composition: `Ruby::Rego.compile_modules` / `evaluate_modules` compile
  and evaluate a named set of modules with cross-package references and OPA-style
  same-package merge.
- Documentation refresh, architecture notes, and runnable examples.
- YARD documentation for public APIs.

## 0.1.0

### Features

- Lexer, parser, and AST support for core Rego syntax.
- Compiler that validates, indexes, and freezes rules.
- Evaluator with rule execution, unification, and reference resolution.
- Core built-in functions (types, aggregates, strings, collections, comparisons).
- CLI for validation workflows.

### Planned additions

- Expanded built-in function coverage.
- Broader OPA compatibility for advanced keywords and patterns.
- Performance tuning and memoization work.
- Compliance and integration test suites.
