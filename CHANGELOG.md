# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- `units.parse_bytes` now computes in a 64-bit `big.Float` exactly as OPA does, instead of exact
  rational arithmetic. OPA parses the amount to a precision-64 binary float (`big.Float.SetString`),
  multiplies by the unit at that precision, then truncates the product toward zero (`big.Float.Int`),
  so a fractional amount whose binary approximation lands just under an integer truncates down:
  `units.parse_bytes("0.001mb")` is now `999` (was `1000`), `units.parse_bytes("9999999999.99999999995")`
  is `10000000000`, and a large-exponent amount differs from the exact integer in nearly every digit.
  Binary-exact amounts (`1.5kib` → `1536`, `10.7` → `10`) are unchanged. Verified vs `opa eval` 1.17.1
  across ~12,000 inputs (a fractional-amount golden set, a 5300-input high-significant-digit
  double-rounding fuzz, and a 5900-input grammar cross-product), zero mismatches.

- `units.parse` now returns a non-integer result as a precision-preserving arbitrary-precision
  number rendered to exactly 10 decimal places (OPA's `big.Rat.FloatString(10)`), instead of a lossy
  Ruby `Float`. Trailing zeros are kept and rounding is half-away-from-zero, matching OPA's
  `json.Number` text byte-for-byte: `units.parse("0.0015K")` is now `1.5000000000` (was `1.5`),
  `units.parse("1000m")` is `1.0000000000` (was `1.0`), and `units.parse("10.5")` is `10.5000000000`.
  A value that rounds to zero keeps its sign and 10 decimals (`units.parse("-0.00000000001")` →
  `-0.0000000000`) because its unrounded value is non-integer; an integer-valued result stays an exact
  integer (`units.parse("10.5K")` → `10500`, `units.parse("0.0")` → `0`). Verified vs `opa eval`
  1.17.1 across a 544-input cross-product. `units.parse_bytes` is unaffected (it already returns an
  exact integer). Known limitation (pre-existing, shared by every number-returning builtin): because a
  number's canonical identity is its numeric value, an integer-valued result like `1.0000000000` dedups
  against the integer `1` inside a set or as an object key, and the representation kept in output is the
  first one seen — matching how OPA's own `1 == 1.0` numeric identity behaves.

- `units.parse` now parses the numeric amount exactly the way OPA's `big.Rat.SetString` does, fixing
  three grammar divergences between Ruby's `Rational` and Go's `big.Rat` (verified vs `opa eval` 1.17.1
  across a 1079-amount grammar cross-product). A bare-dot amount with no mantissa digit (`.`, `+.`,
  `-.`, `.K`) and a dangling exponent (`e`/`E` with a sign but no digits: `1e+`, `1e-`, `.1e+`,
  `1e+K`) are now undefined (were `0`/the mantissa value — Ruby accepts both, Go rejects them; this
  closes a fail-open). A trailing dot immediately before an exponent (`5.e3`, `12.E3`, `5.e-3K`) is now
  accepted (was undefined — Ruby's `Rational` rejects `5.e3`, Go reads it as `5e3`). Forms that already
  matched (`5.`, `.5`, `.5e3`, `1e` as the exa unit, leading zeros, signs) are unchanged.

- `units.parse`/`units.parse_bytes` are now undefined for a non-ASCII or invalid-UTF-8 operand, matching
  OPA (a valid quantity is pure ASCII, so any non-ASCII byte fails the number/unit parse). Previously an
  invalid-UTF-8 operand raised an uncaught `ArgumentError` from Ruby's `String#delete`/`downcase` that
  escaped the builtin and aborted the whole policy (a denial of service); it now yields undefined.

- `yaml.unmarshal` now matches go-yaml's int64/uint64 integer range for prefixed, tagged, and
  object-key integers, verified vs `opa eval` 1.17.1. go-yaml resolves an integer via
  `strconv.ParseInt` (int64) then `ParseUint` (uint64); `ParseUint` rejects a sign, so an
  explicitly `+`/`-` signed value is bounded by int64, while an unsigned value may reach uint64 max.
  - A `0x`/`0o`/`0b` literal outside that range can't be reparsed as a float, so it falls back to
    its verbatim string token instead of becoming an exact bignum:
    `yaml.unmarshal("0x10000000000000000")` is now `"0x10000000000000000"` (was the number
    `18446744073709551616`), `+0x8000000000000000` is `"+0x8000000000000000"` (a signed value past
    int64 max — was a number), and likewise for `-0x…` past int64 min and `0o…`/`0b…` past uint64.
    At the boundary it stays exact (`0xFFFFFFFFFFFFFFFF` → `18446744073709551615`).
  - An `!!int` outside the range is undefined for **every** base (the tag has no float/string
    fallback), so `!!int 18446744073709551616`, `!!int +9223372036854775808`, and
    `!!int 0x10000000000000000` are undefined, matching OPA.
  - An `!!int`/`!!float` whose token does not start with a numeric lead (sign, digit, or dot —
    go-yaml's `resolveTable` first-byte dispatch) is undefined, so a leading-underscore token like
    `!!int _5` or `!!float _5.0` is now undefined (was the number `5`); an interior or trailing
    separator (`!!int 1_0`, `!!int 5_`, `!!int +_5`) is still accepted, matching OPA.
  - An `!!float` coerces an integer-resolved value to a float, so a `0x`/`0o`/`0b` or decimal integer
    in int64 range becomes a float (`!!float 0x5` → `5`, was undefined). But an **unsigned** uint64-band
    value resolves as a Go `uint64`, which has no float coercion, so `!!float 9223372036854775808` is
    now undefined (was a number); a signed or over-uint64 value resolves via `ParseFloat` and stays a
    number. A float64-overflowing `!!float` (e.g. `!!float 1e309`) is undefined in **every** position,
    including as an object key (it was wrongly canonicalized to a `".inf"` key), matching OPA.
  - An **unsigned integer-resolved** object **key** in the positive uint64-only band (above int64 max, up to
    uint64 max) decodes to a Go `uint64`, which `sigs.k8s.io/yaml` cannot stringify as a JSON key, so
    the whole document is undefined: `yaml.unmarshal("9223372036854775808: v")` is now undefined (was a
    defined object). A **signed** key (`ParseUint` rejects the sign), or a **float-resolved** key (plain
    float syntax or a `!!float` tag) that rounds into that band, is a float64 key and stays defined —
    `+9223372036854775808: v` and `9.2e18: v` are defined. An int64-range or over-uint64 key is too.

  - A bare decimal or leading-zero octal that overflows float64 to `±Inf` (e.g. a 400-digit integer,
    `2`×10³⁰⁸) is a string like any other overflow, so `yaml.unmarshal("1" + "0"*400)` is now that
    digit string (was an exact bignum), and the same `!!int` is undefined. This also bounds the parse:
    such a value is rejected before a multi-megabyte bignum is built.

  A bare decimal or leading-zero octal *within* float64 range but past int64/uint64 still parses to an
  exact integer rather than go-yaml's lossy float64 — a separate output-formatting divergence (values,
  and the lossy-float text of signed/float/over-uint64 object keys) tracked for the number sweep. One
  exotic corner is also deferred: a non-uint64 value (a signed integer, or a float that rounds into the
  band) reached via a YAML **alias** key stays undefined here, where OPA defines it — the alias loses the
  anchored scalar's sign/float provenance, which the resolved value alone can't recover.
- `yaml.unmarshal` now renders a float64-overflowing plain decimal as its original string text,
  matching `opa eval` 1.17.1 / go-yaml. A scalar like `1e999` overflows float64 to `±Inf` during the
  YAML→JSON round-trip and falls back to its verbatim text. In **value/bare-scalar** position this was
  previously undefined for the whole document: `yaml.unmarshal("v: 1e999")` is now `{"v": "1e999"}`
  (was undefined) and a bare `1e999` is now `"1e999"` (was undefined). In **object-key** position it
  was previously defined but mis-canonicalized to the infinity token — `yaml.unmarshal("1e999: x")`
  was `{".inf": "x"}` and is now the correct `{"1e999": "x"}`. An underflowing decimal (`1e-999`,
  `1e-400`) is a finite `0.0` and still resolves to the number `0`. An explicit `!!float` tag still
  demands a real float, so `yaml.unmarshal("v: !!float 1e999")` remains undefined, as in OPA. A
  genuinely non-finite value (`.inf`/`.nan`) is still undefined.
- `to_number(string)` now preserves OPA's verbatim `json.Number` text and is byte-exact with `opa eval`
  1.17. A numeric string keeps its exact form — `to_number("1.50")` is `1.50` (was `1.5`), `100.00`
  stays `100.00`, `1E5` stays `1E5`, `-0` keeps its sign, and a large integer stays exact — instead of
  collapsing to `Float`. It accepts exactly the strict JSON-number grammar within float64 range:
  `to_number("1e308")` is fine, `to_number("1e309")` (and any string overflowing float64 to infinity,
  integers included) is undefined, matching OPA. Totality is preserved against untrusted input — an
  invalid-encoding string, a malformed grammar (`1.2.3`), and an over-large/over-tiny magnitude
  (`1e-1000000000`) all map to undefined rather than raising or materializing a giant rational (a memory
  DoS the magnitude cap bounds before the value is built). One **deliberate, documented** divergence:
  OPA additionally accepts `strconv.ParseFloat`-finite-but-non-JSON forms (`007`, `.5`, `+5`, `0x1p4`)
  in comparison/arithmetic while crashing on marshal; the gem routes those to undefined, because storing
  their verbatim text would reinstate the unmarshalable-`json.Number` serializer DoS. This is
  more-strict, not "safe" — it shifts those inputs to undefined, which flips allow vs deny by rule
  polarity. Internally, `to_number` and the JSON decoder now share one number-build path and one
  authoritative grammar source on `Ruby::Rego::Number` (no silent regex drift between the two sites).
- Arbitrary-precision JSON parsing: `json.unmarshal`, `json.is_valid`, `io.jwt.decode`, and the
  `rego-validate` CLI's JSON input/data loader now decode through a new strict, number-text-preserving
  JSON decoder (`Ruby::Rego::JsonDecoder`) instead of Ruby's `JSON.parse`. A JSON number keeps OPA's
  verbatim `json.Number` text — `1.50` stays `1.50`, `100.00` stays `100.00`, `1e999` stays a usable
  number (previously it collapsed to `Float::INFINITY`), `-0` keeps its sign, and a large integer
  stays exact — so `json.marshal(json.unmarshal(x))` round-trips byte-exact with OPA. This closes a
  **fail-open**: a large number from untrusted input (e.g. `input.count`) used to overflow to `Float`
  infinity and leave a comparison like `input.count > limit` undefined, silently passing a deny guard;
  it now compares correctly. The decoder is also strict like Go's `encoding/json` (which OPA uses):
  it rejects `//`/`/* */` comments (closing a gem-wide leniency Ruby's `JSON.parse` had), trailing
  commas, leading zeros, a bare `.5`/`1.`, `NaN`/`Infinity`, and trailing content; duplicate object
  keys take the last value; and an unpaired `\uXXXX` surrogate becomes U+FFFD — all matching OPA.
  `io.jwt.decode` gains the same fidelity, and a divergence is fixed: a JWT header/payload with a lone
  surrogate now decodes to U+FFFD (matching OPA) rather than undefined. Totality is preserved — the
  decoder maps every malformed, truncated, deeply nested (capped at depth 100, as before, to bound the
  recursive value builder), binary, or over-large-magnitude input to undefined rather than raising or
  overflowing the stack — including a string in an ascii-compatible single-byte non-UTF-8 encoding
  (ISO-8859-1 / Windows-1252) carrying a high byte plus a `\uXXXX` escape, which is normalized to bytes
  up front rather than raising an uncaught `Encoding::CompatibilityError`. Two residual divergences
  remain, neither blocking: (1) nesting deeper than 100
  is undefined where OPA decodes to ~10000 — gem-stricter, a deliberate stack-overflow guard. (2) A
  number whose magnitude exceeds ~`1e30102` (the same cap the lexer applies to literals) makes the
  document undefined, where OPA evaluates it (OPA itself only panics at a ~19-digit exponent). The cap
  bounds rational materialization — without it, comparing `1e1000000` would allocate a million-digit
  rational (a memory DoS) — so this trades a DoS for a **narrowed-but-not-closed fail-open**: in a deny
  guard, a number above the cap goes undefined (deny does not fire) where OPA would compare it and deny.
  The realistic range, including `1e999` and far beyond, is closed; the residual window above `1e30102`
  is closed properly by the deferred no-materialize comparison work (tracked follow-up). **The fail-open
  closure is JSON-input only**: YAML input/data still parses through `YAML.safe_load`, which collapses
  `1.50`→`Float` and reads `1e999` as a bare `String`, so the comparison fail-open persists for YAML
  policy input; routing YAML through the gem's scalar resolver is a tracked follow-up.
- New built-in: `providers.aws.sign_req(request, aws_config, time_ns)`, matching OPA — signs an HTTP
  request (http.send shape) with AWS Signature Version 4 and returns the request copied with its
  `headers` replaced by the original headers plus the signing headers (`Authorization`, `host`,
  `x-amz-date`, and conditionally `x-amz-content-sha256` for s3/glacier and `x-amz-security-token`).
  The signing time is the `time_ns` argument (deterministic). It is a faithful port of OPA's signer
  (internal/providers/aws/signing_v4.go), including the three ways OPA's SigV4 deviates from the AWS
  spec: the canonical query string is the URL's raw query verbatim (not sorted/re-encoded), header
  values are signed un-trimmed, and the canonical URI is Go's `url.EscapedPath()` (user percent-
  encoding preserved, never double-encoded). The body is hashed from `raw_body` (a string, taking
  precedence over `body`) or `json.marshal(body)`, which the arbitrary-precision number model makes
  byte-exact with OPA — so a body number written as a Rego literal (`1.50`, `1e10`) hashes identically
  to OPA, where it previously diverged. (A body number arriving from parsed JSON input still collapses
  through `Float`, the deferred input-precision gap, so exact-byte callers pass `raw_body`.) Any
  precondition failure is undefined
  (non-object request/config; a request key outside http.send's allowed set or a missing/non-string
  method/url; an unparseable url; an `aws_config` missing one of the four required string keys — empty
  strings are accepted — or holding a non-string for one; a non-integer / int64-overflowing `time_ns`;
  or a non-boolean `disable_payload_signing`). The signed output is byte-exact with OPA, verified
  differentially against `opa eval` 1.17.

- Numbers are now an OPA-faithful arbitrary-precision model instead of Ruby `Float`. A non-integer
  literal becomes a `Ruby::Rego::Number` that preserves its source text verbatim (OPA's `json.Number`
  model: `1.50` stays `1.50`, `-1.50` stays `-1.50`, `-0.0` stays `-0.0`, `1e999` stays `1e999`,
  `1e308` no longer becomes `1e+308` in `json.marshal`), and arithmetic runs through Go's
  `math/big.Float` model — reproduced with the `flt`
  gem at 64-bit binary precision and round-half-even — so computed results match OPA byte-for-byte
  (`1/3` → `0.33333333333333333334`, `0.1 + 0.2` → `0.3`, `0.3 - 0.1` → `0.20000000000000000002`,
  `1e308 * 1e308` → the full ~600-digit integer). Division is always big.Float (`5 / 2` → `2.5`, an
  integer-valued quotient like `4 / 2` collapsing to `2`); modulo is integer-valued-only and otherwise
  undefined (`4.0 % 2` → `0`, `5.5 % 2` → undefined) with Go's truncated remainder (`-5 % 3` → `-2`).
  Integers stay Ruby `Integer` (already arbitrary-precision); `1 == 1.0` / `1.50 == 1.5` equality and
  the first-seen-representation dedup are unchanged. This closes the serializer denial-of-service where
  `x := 1e999` or `1e308 * 1e308` produced a non-finite `Float` that crashed `Result#to_json`: numbers
  are now always finite and serialize as their canonical text. Builtins that classify numbers learned
  about the new type so behaviour is unchanged from before: `round`/`ceil`/`floor` of a beyond-Float
  magnitude return a finite integer instead of raising `FloatDomainError` (a totality fix), and an
  integer-valued literal in float form (`3.0`) is still accepted wherever an integer is required
  (`numbers.range`, `bits.*`, `format_int`, `json.match_schema` `type: integer`, `yaml.marshal`), and
  `numbers.max` / `numbers.min` return the last of value-equal ties (so `max([1.50, 1.5])` is `1.5`),
  matching OPA. A numeric literal whose magnitude is beyond OPA's limit (≈`1e±30102`) is now rejected
  at parse with a "number too big" error, exactly as OPA does — this also bounds the rational the
  number would otherwise materialize, closing an unbounded-exponent denial of service (`1e999999999`,
  12 source bytes, previously allocated a gigabyte-scale rational). Verified differentially against
  `opa eval` 1.17. `round`/`ceil`/`floor` round the precision-64 binary value exactly as OPA's
  big.Float does (so `round(0.4999…9)` is `1` and `round(1e400)` matches OPA's rounded integer
  byte-for-byte). (Not yet migrated — tracked for the builtin number sweep: `to_number`,
  `units.parse` and the numeric/aggregate builtins still round-trip through `Float`, and
  `json.unmarshal` collapses number text.)
- An invalid-UTF-8 / ASCII-8BIT (binary) string in an evaluation result — most easily an object key
  from `base64.decode` — now serializes like Go's `encoding/json` (each invalid byte → `U+FFFD`,
  byte-for-byte with OPA) instead of raising `JSON::GeneratorError` and aborting the policy. A number
  beyond `Float` range read from `input`/`data` JSON (e.g. `{"n": 1e999}` → `Float::INFINITY`, or YAML
  `.nan`) is now mapped to undefined at the value boundary, so arithmetic, comparison, aggregation and
  serialization over it all stay total instead of raising; preserving such input values is tracked for
  the arbitrary-precision input/`json.unmarshal` sweep. **Note** this means a comparison or equality
  against such an input value is now undefined where it previously returned a (sometimes-correct)
  boolean — e.g. a `input.n > threshold` guard does not fire when `input.n` is `1e999`; treat numbers
  beyond `Float` range in untrusted input as undefined until that sweep lands.

- Known deferred number divergences from OPA (tracked for the builtin number sweep, unchanged from
  before this work): integer `+`/`-`/`*` stays exact past 2^64 whereas OPA rounds every operation
  through a 64-bit big.Float (`2^64 + 1` is `2^64` in OPA); `yaml.marshal` of a magnitude beyond
  float64 range is undefined whereas OPA emits the `json.Number` text; `to_number` / `units.parse` and
  `json.unmarshal` still round-trip non-integer numbers through `Float`.
- Known limitation (tracked follow-up): comparing/ordering/deduplicating very large numbers of distinct
  near-magnitude-limit literals (e.g. tens of thousands of `1e30102`) materializes a large exact
  rational per literal, so a pathological policy can use substantial memory. On the previous `Float`
  model the same input crashed serialization outright; making the equality/compare path avoid
  materializing the full rational for extreme magnitudes is a separate change.

- `json.match_schema` now enforces the gojsonschema `format` assertions OPA implements for the
  lexical / date-time / network / regex / URI / email formats: `hostname`, `uuid`, `json-pointer`,
  `relative-json-pointer`, `regex`, `date`, `time`, `date-time`, `ipv4`, `ipv6`, `uri`,
  `uri-reference`, `iri`, `iri-reference`, `uri-template`, `email`, `idn-email`. Rules mirror
  gojsonschema's format_checkers.go exactly (whole-text `\A..\z` anchoring, Go `time.Parse`
  semantics incl. comma-or-period fractional seconds and a loosely range-checked zone offset,
  proleptic-Gregorian dates, `net.ParseIP`-equivalent IPs, and Go `net/url.Parse` for the URI
  family — reusing the gem's `uri.parse` port, with a non-empty-scheme requirement for `uri`/`iri`,
  an explicit backslash reject, and the template path regex for `uri-template`; `iri*` are exact
  aliases of `uri*`). `email`/`idn-email` run Go's `net/mail.ParseAddress` (a full RFC 5322 address
  parse, not a "valid email" regex; `idn-email` is the same checker). The formats OPA does not
  enforce (`idn-hostname`, `duration`, unknown names) stay annotation-only (no-op). The boolean
  result stays byte-exact with OPA for the enforced formats.

- Security / behavior change: an untrusted regex (`pattern`, `patternProperties`, and the new
  `format: "regex"`) is now compiled under two bounds — a 64 KB RE2 program budget (compile phase)
  and a 4 KB pattern-bytesize cap (parse phase) — and `match_schema` memoizes each distinct pattern
  per call. The re2 gem's C++ RE2 compiles adversarial patterns far slower than Go's `regexp`
  (which OPA uses): without these, a ~3 KB nested-repetition pattern took tens of seconds, a class-
  dense pattern was linear-unbounded, and `patternProperties` recompiled N×M times — all CPU
  denial-of-service vectors that the previous code (and the default 8 MB budget) did not bound.
  Trade-off: a pattern whose RE2 program exceeds 64 KB or whose text exceeds 4 KB is now reported
  invalid / non-matching where OPA accepts it — a documented divergence on adversarial inputs;
  every realistic pattern (and the existing pattern test corpus) is unaffected.

- New built-in: `time.format`, matching OPA — formats an instant (`ns`, `[ns, tz]`, or
  `[ns, tz, layout]`) using Go's reference-time layout language (the `2006-01-02 15:04:05` token
  scheme). The layout defaults to RFC3339Nano, accepts the named constants (ANSIC, UnixDate,
  RubyDate, RFC822/Z, RFC850, RFC1123/Z, RFC3339, RFC3339Nano), or any literal Go layout. The
  formatter is a direct port of Go's stdlib (nextStdChunk + appendFormat + appendNano), so the
  fiddly cases match Go exactly: `Z07:00` prints `Z` for UTC, `.999`-style fractions trim trailing
  zeros (dropping the separator when zero) while `.000` stays fixed-width, `_2` space-pads, and the
  `MST` token uses the IANA abbreviation (including numeric forms like `-05`/`+14`). An unknown zone
  or wrong-typed operand is undefined. The same far-future DST-projection caveat as the other
  tz-aware time builtins applies.

- New built-in: `time.add_date`, matching OPA (Go's Time.AddDate) — adds integer years/months/days
  to an instant (`ns` or `[ns, tz]`), keeping the wall clock and zone, and returns nanoseconds.
  Calendar overflow rolls forward like Go's time.Date (e.g. Jan 31 + 1 month -> Mar 2), not
  clamped; the result wall clock is re-anchored in the operand's zone, resolving a DST gap or
  overlap exactly as Go does. An out-of-int64 result, a non-integer count, or an unknown zone is
  undefined. The same far-future DST-projection caveat as the other tz-aware time builtins applies.

- New built-in: `time.diff`, matching OPA — the calendar difference between two instants (each a
  bare ns number, UTC, or `[ns, tz]`) as a non-negative `[years, months, days, hours, minutes,
  seconds]` tuple. Both instants are decomposed in the first operand's timezone (the second
  operand's zone is still resolved, and so validated); a wrong-typed operand or an unknown zone
  on either side is undefined. The same far-future DST-projection caveat as the other tz-aware
  time builtins applies.

- New built-ins: `time.date`, `time.clock`, and `time.weekday`, matching OPA. Each decomposes an
  instant given as nanoseconds since the Unix epoch — a bare number (UTC) or `[ns, tz]` where `tz`
  is `""`/`"UTC"`, `"Local"`, or an IANA timezone name (resolved via the new `tzinfo`/`tzinfo-data`
  dependencies, which pin the timezone database for deterministic, host-independent results).
  `time.date` returns `[year, month, day]`, `time.clock` `[hour, minute, second]`, and
  `time.weekday` the English weekday name. A third array element (a layout, used only by
  `time.format`) is accepted and ignored. A non-integer or out-of-int64 ns, a non-string or unknown
  tz, an empty array, or a wrong-typed operand is undefined. Note: for DST-active instants past
  tzinfo's last generated transition for the zone (e.g. ~2127 onward for `America/New_York`) in
  daylight-saving timezones, the result may differ from OPA by the DST offset, because Ruby's
  tzinfo stops emitting transitions there while Go's bundled tzdata projects the POSIX TZ rule
  indefinitely; within any practical range the output is byte-exact.

- New built-ins: `time.parse_rfc3339_ns` and `time.parse_duration_ns`, matching OPA. The former
  parses a strict RFC 3339 timestamp (uppercase `T`/`Z`, a required `Z` or `±HH:MM` zone, a
  fractional second of any length truncated to nanoseconds, a valid calendar date/time) to
  nanoseconds since the Unix epoch, and is undefined outside the int64-nanosecond range. The latter
  parses a Go duration (signed, fractional, units ns/us/µs/ms/s/m/h, with `0` a valid zero) plus
  OPA's `d`/`w`/`y` extension (24h/168h/8760h); the result must fit int64 nanoseconds. A
  non-string or unparseable input is undefined.

- New built-in: `json.marshal_with_options`, matching OPA — marshals a value to JSON with optional
  formatting. The options object takes `prefix` and `indent` strings and a `pretty` boolean;
  pretty-printing uses Go's json.MarshalIndent indent-per-depth layout, with the `prefix` (matching
  OPA) prepended to every line including the first, and is
  enabled by `pretty: true`, or implicitly when `prefix` or `indent` is given without an explicit
  `pretty`. Compact output matches `json.marshal` (sorted keys, HTML escaping). A non-object
  options argument, an unknown option key, a wrongly-typed option value, or an unmarshalable
  document yields undefined.

- New built-in: `json.patch`, matching OPA — applies an RFC 6902 operation list (add, remove,
  replace, move, copy, test) to a document. Paths are RFC 6901 JSON pointers (`~1` for `/`, `~0`
  for `~`; a leading run of slashes is stripped; the empty string `""` is the whole document,
  while an all-slash pointer such as `/` or `//` addresses the empty-string key `""`) or an array
  of segments (a string key, or a string/integer array index). Operations apply in order; any
  failure — a non-array operand, an operation that is not an object, a missing or invalid field,
  a path into a non-existent or scalar location, an out-of-range array index, or a failed `test`
  — yields undefined. `test` compares by value (so `1` matches `1.0`).

- New built-in: `net.cidr_merge`, matching OPA (a port of Cilium's algorithm). It merges a list
  (array or set) of IP addresses and CIDRs into the smallest set of CIDRs covering exactly the
  same addresses — combining adjacent subnets, absorbing contained ones, and removing duplicates.
  A bare IPv4 address takes its classful default mask (Go's `net.IP.DefaultMask`); a bare IPv6
  address is undefined (a prefix is required), as is a non-string element, an unparseable element,
  or a non-collection operand. IPv4 ranges are merged inside their IPv6-mapped (`::ffff:`) block,
  so a containing IPv6 range (e.g. `::/0`) absorbs IPv4 entries exactly as OPA does. A CIDR is
  masked to its network; a bare address keeps its host form unless it is merged. IPv6 output uses
  an RFC 5952 renderer matching Go's `net.IP.String()` (no deprecated IPv4-compatible `::a.b.c.d`
  form).

- New built-in: `uuid.parse`, matching OPA's `internal/uuid` (a port of google/uuid). It returns
  an object with `version` and `variant` for every UUID, plus `time` (nanoseconds since the Unix
  epoch), `nodeid`, `macvariables`, and `clocksequence` for time-based versions 1 and 2 (and `id`
  and `domain` for the DCE version 2). Canonical, unhyphenated, `urn:uuid:`-prefixed, and
  brace-wrapped forms are accepted (case-insensitive); a non-string or an unparseable UUID is
  undefined. The `time` field matches OPA's int64 arithmetic, including its silent overflow for
  the extreme (non-real) timestamps at the ends of the 60-bit range. (`uuid.rfc4122` is not yet
  implemented: it is a per-evaluation random generator that needs evaluator-scoped builtin state.)

- Fix: numerically-equal numbers (e.g. `1` and `1.0`, `1.5` and `1.50`) are now treated as the
  same value for equality and hashing, matching OPA (where `1 == 1.0`). The `Value` layer
  compares and hashes on a canonical form (an integer-valued `Float` collapses to its `Integer`)
  applied recursively through arrays, sets, and objects, while `to_ruby` keeps the first-seen
  representation. This fixes set deduplication and equality across the board: `count({1, 1.0})`
  is now `1` (was `2`), `{1} == {1.0}` is `true` (was `false`), and the same holds for nested
  collections (`{[1], [1.0]}`, `{{1}, {1.0}}`, objects with numeric members) and for set
  comprehensions, partial-set rules, membership, and the `union`/`intersection`/`set_diff`
  helpers. Object construction and lookup are normalized for the common cases: numerically-equal
  object keys collapse to one entry keeping the first key form and last value (`{1: "a", 1.0:
  "b"}` is `{1: "b"}`, `{1.0: "a", 1: "b"}` is `{1.0: "b"}`), `count` of such an object is `1`,
  `object.keys` de-duplicates, and `object.get`/reference lookup find a value by numeric equality
  (`object.get({1.0: "v"}, 1, _)` is `"v"`).

  Known limitations (rare; rooted in object-literal/partial-rule/unifier construction internals,
  not the value layer): when numeric keys are *duplicated or conflict within a single construct*,
  the result can diverge from OPA. A literal repeating an exact key alongside a numeric alias
  (`{1: "a", 1.0: "b", 1: "c"}`) may pick the wrong duplicate's value; a partial-object rule with
  numerically-equal keys and different values (`p[1] := "a"`, `p[1.0] := "b"`) silently keeps one
  value where OPA raises a conflict (**fail-open vs OPA's fail-closed**); and object destructuring
  patterns (`{1: x} = {1.0: v}`) don't match across numeric aliases. Out of scope and
  pre-existing: numbers larger than 2^53 written in float form lose precision (the gem uses Ruby
  `Float`, not OPA's arbitrary-precision number), and `union`/`intersection` take two sets here
  rather than OPA's single set-of-sets.

- Small collection & graph built-ins: `array.flatten`, `object.subset`, `graph.reachable`,
  and `graph.reachable_paths`, matching OPA. `array.flatten` flattens exactly one level (a
  directly-nested array's elements are spliced in; deeper arrays are left intact).
  `object.subset(super, sub)` is true when `sub` is contained in `super`: objects recursively,
  sets by membership, arrays as a contiguous subslice, and an array-super/set-sub by coverage;
  any other operand pairing yields undefined. `graph.reachable(graph, initial)` returns the set
  of reachable nodes and `graph.reachable_paths` the set of walkable paths (both stop at cycles;
  a neighbour that is not itself a node in the graph is not reached, as in OPA). Hand-rolled; no
  new dependency. (`uuid.rfc4122` is not implemented — it is non-deterministic, so it cannot be
  reproduced byte-for-byte, like `rand.intn`.) `object.subset` compares set members and object
  keys with numeric equality (1 and 1.0 match, as OPA does); `graph.*` node identity, however,
  uses plain Hash/Set membership, so a graph mixing integer and float forms of the same node
  label can diverge — part of the known SetValue/ObjectValue numeric-normalisation gap
  (`count({1, 1.0})` is 2 here, 1 in OPA), to be addressed at the value layer in a later change.

- Units built-ins: `units.parse` and `units.parse_bytes`, matching OPA. `parse` reads an
  SI/binary quantity (`10K`, `1.5Mi`, `10m`) to a number — note the m/M asymmetry (lowercase
  `m` is milli, uppercase `M` mega; every other first letter is case-insensitive) — returning
  an integer or a value rounded to 10 decimals. `parse_bytes` reads a byte quantity (`10KB`,
  `1.5GiB`; case-insensitive, `b`-suffixed or bare, but a lone `b` is not a unit) to an
  integer, truncating toward zero. A space, an empty/unparseable amount, an unknown unit, a
  non-string, a scientific exponent over 6 digits, or an operand over 1M characters (a DoS
  bound OPA lacks) yields undefined. Hand-rolled with exact
  rational arithmetic; no new dependency. One intentional divergence: `parse_bytes` uses exact
  arithmetic where OPA uses `big.Float`, so a fractional amount whose binary approximation
  falls just below an integer truncates one lower in OPA (e.g. `0.001mb` → 999 there, 1000
  here — the value OPA's own `units.parse("0.001M")` returns).

- Net/CIDR built-ins: `net.cidr_expand` and `net.cidr_contains_matches`, matching OPA.
  `cidr_expand(cidr)` returns the set of every address in a CIDR (host bits masked to the
  network first); the argument must be a valid CIDR (a bare IP is undefined), and a block
  larger than ~1M addresses yields undefined (OPA relies on Go's runtime; this is a DoS
  bound). `cidr_contains_matches(cidrs, addrs)` returns the set of `[cidr_key, addr_key]`
  pairs where a CIDR contains an address — each operand may be an array (key is the index),
  object (key is the key), set or scalar (key is the element itself); a first-collection
  element must be a CIDR, a second an IP or CIDR, and any non-string or unparseable element
  yields undefined. Both build on the existing `IPAddr`-backed parsing (IPv4/IPv6,
  IPv4-mapped normalisation); no new dependency. (`net.cidr_overlap` is intentionally
  omitted — OPA deprecated it and rejects it at compile time.)

- Fix: an empty array literal `[]` now parses in every position (rule value, nested,
  object/set value, function argument). The parser recognized `[]` but did not consume the
  closing `]`, leaving it dangling so any enclosing construct failed (e.g. `count([])` →
  "Expected ')' after arguments", `x := []` → "Expected rule identifier"). Empty `{}` was
  unaffected. Now consumes the bracket like the empty-object/empty-set paths.

- Fix: `json.marshal` now orders set elements by OPA's term order even when an element is a
  composite. The previous implementation ranked elements *after* converting them to JSON, which
  lost type information: a nested set was ranked as an array (so `json.marshal({ {"a": 2}, {2, 3} })`
  returned `[[2,3],{"a":2}]` instead of OPA's `[{"a":2},[2,3]]`), and a set of objects with
  non-string keys was ranked by stringified keys (so `{ {2: "x"}, {10: "x"} }` ordered as `"10"`
  before `"2"` instead of numerically). Set element ordering is now sorted on the raw value
  before conversion, via a new `Builtins::TermOrder` helper shared with `yaml.marshal`. Sets of
  scalars, arrays, and string-keyed objects are unaffected.

- YAML built-ins: `yaml.marshal`, `yaml.unmarshal`, and `yaml.is_valid`, matching OPA (which
  vendors sigs.k8s.io/yaml over gopkg.in/yaml.v2 via a JSON round-trip). Built on Psych
  (libyaml — the engine yaml.v2 ports), so layout, line-folding, escaping, and the
  plain→single/double quote downgrade match for free; only the divergent pieces are
  hand-supplied. `marshal` sorts object keys, formats floats with Go's `strconv` `'g'`
  shortest rules (`1.0`→`1`, `1e6`→`1e+06`), emits `nil` as `null`, double-quotes strings
  that would otherwise resolve to a non-string/timestamp/base-60, stringifies and sorts
  non-string keys, and replaces invalid UTF-8 with U+FFFD. `unmarshal` resolves plain scalars
  with a yaml.v2-compatible resolver (yes/no/on/off bools, hex/octal/binary/underscored ints;
  timestamps stay strings; integer-valued floats collapse to ints), honors explicit core
  tags (`!!str`/`!!int`/`!!float`/`!!bool`/`!!null`, yielding undefined on an uncoercible
  value like `!!int "abc"`), stringifies object keys (a null or composite key yields
  undefined, as JSON cannot key on it), resolves anchors/aliases and merge keys, takes the
  first document (an empty document is null); invalid YAML or a non-finite number yields
  undefined. `is_valid` is total over runtime values (a non-string
  yields `false`). DoS bounds (source length, nesting depth, expanded-node count → undefined,
  since OPA relies on Go runtime limits absent here) guard deep nesting, cyclic anchors, and
  alias-expansion bombs. Uses Psych (Ruby stdlib; no new gem) via the AST API, never
  `Psych.load`, so there is no object-instantiation surface. One intentional divergence: a
  finite non-integer float map key formats with Ruby float64-shortest, whereas OPA uses Go
  float32 — a rare edge; values and all other keys are byte-exact.

- Regex built-in: `regex.globs_match`, matching OPA — true when two restricted-regex globs
  share a common non-empty match. A faithful port of OPA's github.com/yashtewari/glob-intersection
  (tokenizer plus recursive intersection engine), bug-for-bug including its quirks (e.g.
  `abc.*` vs `abc` is `false`). Invalid globs yield undefined; DoS bounds (source length, flag
  count, class-range size, intersection work → undefined) guard the algorithm, which is
  exponential in the smaller glob's flag count. Hand-rolled; no new dependency.

- Numeric built-in: `numbers.range_step(low, high, step)`, matching OPA — an integer range
  from low toward high by a positive integer step, including the endpoint only when it lands
  exactly on a step (ascending or descending by the bound order). A non-positive or
  non-integer step yields undefined; integer-valued floats are accepted. Shares
  `numbers.range`'s allocation guard.

- Regex built-ins: `regex.find_all_string_submatch_n` and `regex.template_match`, matching
  OPA. `find_all_string_submatch_n(pattern, string, n)` returns each match as
  `[full_match, group1, …]` (non-participating groups become `""`); `n<0` returns all, `n=0`
  an empty array, `n>0` the first n. `template_match(template, string, delim_start, delim_end)`
  matches anchored, with delimited regex sections embedded in literal text; delimiters must be
  a single byte (Go `len()`), an unbalanced or stray delimiter yields undefined, and each
  section is grouped so `{a|b}c` means `(a|b)c`. Reuses the existing regex DoS guards.

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
