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

## 6. Why the other approaches were eliminated

Only the shipped parser actually failed. The other three passed the corpus with zero wrong verdicts;
they were eliminated on diagnostics and cost.

**The shipped nom parser.** 23 wrong verdicts: 20 grammar-valid patterns rejected and 3 invalid ones
accepted, including five of the reference validator's own 23 `spec_examples.txt` cases. The causes
are ordinary: the integer branch wins before the float branch, so `7.0` fails while `.5` works;
`parse_string` stops at the first space, so `'Conference Info'` fails; parenthesised comparison
groups were never implemented; `>=`/`<=` lose to `>`/`<` because of alternative ordering; the
qualifier keywords are `STARTS`/`STOPS` instead of `START`/`STOP`. Comments, escaped quotes,
non-breaking-space whitespace, and binary literals are all missing. Every failure echoes the whole
pattern with no column.

**ANTLR.** It reached 51/51 and has the best structured error data of any candidate: line, column,
byte span, offending token text and token type. But its reason for being favoured was the claim that
computed expected sets would enable "did you mean FOLLOWEDBY?". That does not survive contact: ANTLR
reports at the state *after* the left-recursive operator loop has exited, so the expected set is
`']'` inside the bracket and `<EOF>` outside it. The operator alternatives are structurally absent
from the event, and no formatter can recover them. Add MSRV 1.95, a codegen crate that pulls
`rustpython-vm` and needed a `libc` pin to compile, 314 KB of generated source, and a 28 MB binary.

**chumsky.** It also reached 51/51, but its premise was that labels plus spans produce good messages
cheaply. Every token is padded by a trivia parser, so the expected set includes all 25 whitespace
characters and `/`; keywords are matched by `just("FOLLOWEDBY")`, so a typo reports the first
*mismatching character* rather than the token (`found 'A' expected 'O'`). Labels add to, rather than
replace, the expected set. Reaching user quality needs a lexer or a custom error filter, at 397 LOC
and a 381 MB debug binary.

**The fresh nom probe.** `VerboseError` plus `context()` produces positions and a readable
`convert_error` trace, and coverage was 51/51. But `alt` returns the *last* alternative's error
rather than the deepest one, so a missing value reports "expected a keyword or symbol" instead of the
value kinds. Recovering expected sets needs a custom error type. It took 547 lines, the most code of
any candidate, for the weakest diagnostics.

**pest.** It records the farthest failure of every alternative and unions them, so `I04` reports
`AND`/`OR`/`']'` where ANTLR reported only `']'`, and `I25` includes `FOLLOWEDBY`. It is also the
cheapest: 1 s rebuild, 6.8 MB binary, MSRV 1.88, no codegen dependency. Its one weakness,
hand-maintaining the grammar port, is bounded: the grammar is 237 lines, STIX 2.1 is fixed, and the
port is about 100 lines.

## 7. AST integration spike

The spike builds the real `stixflayer::pattern::expr` AST from pest's pair tree and runs the real
`Stix::stix_check()`. Results are in `results/spike.jsonl`.

```
must-pass ASTs built:  47/51
unexpected stix_check rejects among built cases: 0
semantic mismatches vs baseline: 2  (V43 REPEATS 0, V44 WITHIN 0)
```

Four must-pass patterns cannot be represented by the current AST:

| case | pattern feature | AST gap |
|---|---|---|
| V17 | `[(a OR b) AND c]` | `ComparisonComponent::BooleanOp`'s right-hand side is a single `ComparisonExpression`, so a nested comparison group has no shape |
| V28 | `[file:name NOT = 'x']` | no negation flag on `ComparisonExpression` |
| V49 | `[file:name NOT IN (...)]` | same missing negation flag |
| V29 | `[NOT EXISTS file:name]` | same missing negation flag |

The two semantic mismatches are the same finding seen from the other side: the shipped front end
enforces `REPEATS > 0` and `WITHIN > 0` inside `parse_qualifier`, so `stix_check()` never sees those
values. With pest building the AST, `stix_check()` accepts both. The adoption change has to decide
whether the range rule belongs to the grammar layer or the semantic layer, and move it accordingly.

The AST bridge itself works: left-associative folds, one qualification node per qualifier, flattened
object paths, and lossless `Like`/`Hex`/`Binary`/`Neq` variants all pass assertions. The gaps are in
the *contract*, not the parser.

## 8. Verdict

Pending the final review.
