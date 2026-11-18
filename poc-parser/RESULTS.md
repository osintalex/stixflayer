# STIX Pattern Parser Comparison - Results

**Status:** in progress. All four front ends complete; the winner spike is pending.

## 1. Environment

| Item | Value |
|---|---|
| Date | 2026-11-18 |
| Toolchain | rustc/cargo 1.96.1 (Alpine, musl) |
| Grammar | `STIXPattern.g4` from `cti-stix2-json-schemas` master, 237 lines, SHA-256 `bfe2cd1367705630783c55fb1f9969feb94ed43e27acd0c266e6bc0846f761c1` |
| antlr | `antlr-rust-runtime` 0.34.0, `antlr-rust-codegen` 0.34.0 |
| Reference | `stix2patterns` in `.venv`, ANTLR 4.13.2 Python runtime |
| Corpus | 77 cases: 51 expected-accept, 26 expected-reject, 5 flagged semantic |

Dependency workaround: `antlr-rust-codegen` depends on `rustpython-vm` 0.5.0, which does not
compile against `libc` >= 0.2.186 because `libc::POSIX_SPAWN_SETSID` changed from `c_int` to
`c_short`. `antlr-poc` pins `libc = "=0.2.185"`. Recorded as a cost, not hidden.

## 2. Verbatim showcase

### 2.1 Gate: does the expected set enable "did you mean FOLLOWEDBY"?

`I04` (`[file:name = 'x' FALLOWEDBY [domain-name:value = 'y']]`):

```
1:17: mismatched input 'FALLOWEDBY' expecting ']'
```

`I25`, the same typo after the closing bracket:

```
1:18: mismatched input 'FALLOWEDBY' expecting <EOF>
```

`I06`, invalid month inside a timestamp:

```
1:16: extraneous input 't' expecting {IntNegLiteral, IntPosLiteral, FloatNegLiteral,
FloatPosLiteral, HexLiteral, BinaryLiteral, StringLiteral, BoolLiteral, TimestampLiteral}
```

Conclusion: expected sets are computed at the state where the parser stopped. For an operator
typo, the left-recursive loop has already exited, so the operator token is never in the set. The
official ANTLR reference behaves identically. "Did you mean FOLLOWEDBY?" is not available from
this data; it would need a vocabulary-level fuzzy match on the offending token.

Structured fields that *are* available: line, column, half-open byte span, offending token text
and token type. The expected set exists only as text inside `message`, not as a data structure.

pest differs, and the difference matters:

```
I04  pest:  = expected kw_and, kw_or, or r_bracket
I25  pest:  = expected EOI, qualifier, kw_and, kw_or, or kw_followedby
```

pest reports the union of farthest failures, so the comparison-operator alternatives survive for
I04 (`AND`/`OR`/`]`, versus ANTLR's `]` alone), and `FOLLOWEDBY` is present for I25. "Did you mean
FOLLOWEDBY?" is therefore feasible with pest for the after-bracket typo, but still not for the
brief's inside-bracket case.

## 3. Correctness matrix

See `results/*.jsonl` and `cargo run -p harness --bin compare`.

| implementation | wrong verdicts | semantic divergences | must-pass |
|---|---|---|---|
| baseline (shipped, source-built) | 23 | 4 | 27/51 |
| antlr | 0 | 0 | 51/51 |
| pest | 0 | 0 | 51/51 |
| chumsky | 0 | 0 | 51/51 |
| nom (fresh, VerboseError) | 0 | 0 | 51/51 |

Baseline detail: 20 grammar-valid patterns rejected (including 5 of the reference validator's own
23 `spec_examples.txt` cases) and 3 grammar-invalid patterns accepted (`007`, `STARTS/STOPS`,
`\n` escape). The installed `.so` in `.venv` is stale relative to `main`; the baseline column is
compiled from `rust/` at the current commit.

## 4. Error-quality scoring

| criterion | antlr | pest | chumsky | nom (fresh) |
|---|---|---|---|---|
| position accuracy | line, column, byte span | line, column (span via `line_col` only) | byte span only | line/column, but `alt` collapses to the last alternative |
| message clarity (raw) | recovery vocabulary; confusing for I06 | rule names (`kw_and`, `primitive_literal`) | trivia expectations dominate; keywords fail mid-token | `VerboseError` trace via `convert_error` |
| cascade behaviour | one diagnostic for most cases | one diagnostic | one diagnostic | one diagnostic, sometimes at the wrong alternative |
| structured data | token text/type and span; expected set text-only | expected/negative `Rule` sets as data | found/expected sets and span, polluted by trivia | context stack; no expected sets |
| multi-error | listener receives each diagnostic | one error per parse | available, but one per case here | no |
| formatted (<=50 LOC) | "1:17: expected ']' to close the observation expression, found 'FALLOWEDBY'." | "1:18: expected 'AND' or 'OR' or ']'" | labels add to, rather than replace, the expected set | "1:17: expected ']', found \"FALLOWEDBY \"" |

nom's `VerboseError` + `context()` is workable, but `alt` returns the *last* alternative's error
rather than the deepest one. I01 and I13 therefore report "expected a keyword or symbol" instead of
the value or number that was actually missing; I04 happens to land on "expected ']'" because the
dispatch was restructured around the first character. Recovering expected sets would need a custom
error type that merges alternatives, which is more work than either antlr or pest required. Note
also that nom 8 moved `VerboseError` and `convert_error` to the `nom-language` crate.

chumsky is the weakest diagnostic surface of the four. Every token is padded by a `trivia` parser,
so the expected set includes all 25 whitespace characters and `/`; keywords are matched by
`just("FOLLOWEDBY")`, so a typo reports the first *mismatching character* rather than the token
(`I25`: "found 'A' expected 'O'"). Labels do not suppress the inner expectations. Reaching
user-quality messages here needs a lexer or a custom error filter, which is more work than either
antlr or pest required.

## 5. Cost

| implementation | PoC LOC | direct deps | dep tree lines | rebuild | generated source | debug binary | MSRV |
|---|---|---|---|---|---|---|---|
| antlr | 178 (168 runner + 10 build.rs) | 3 | 30 | 8 s | 314 KB | 28 MB | 1.95 |
| pest | 207 (109 runner + 98 grammar) | 3 | 31 | 1 s | macro only | 6.8 MB | 1.88 |
| chumsky | 397 | 2 | 29 | 19 s | none | 381 MB (debug) | 1.65 |
| nom (fresh) | 547 | 3 | 22 | 1 s | none | 4.2 MB | 1.65 |

The grammar compiled unmodified; no lexer/parser split was required.

## 6. Verdict

Pending the remaining front ends and the winner spike.
