# STIX Pattern Parser Comparison - Results

**Status:** in progress. antlr-rust complete; pest, chumsky, nom, and the winner spike pending.

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

## 3. Correctness matrix

See `results/*.jsonl` and `cargo run -p harness --bin compare`.

| implementation | wrong verdicts | semantic divergences | must-pass |
|---|---|---|---|
| baseline (shipped, source-built) | 23 | 4 | 27/51 |
| antlr | 0 | 0 | 51/51 |

Baseline detail: 20 grammar-valid patterns rejected (including 5 of the reference validator's own
23 `spec_examples.txt` cases) and 3 grammar-invalid patterns accepted (`007`, `STARTS/STOPS`,
`\n` escape). The installed `.so` in `.venv` is stale relative to `main`; the baseline column is
compiled from `rust/` at the current commit.

## 4. Error-quality scoring

| criterion | antlr |
|---|---|
| position accuracy | yes: line, column, byte span |
| message clarity (raw) | ANTLR recovery vocabulary; confusing for I06 |
| cascade behaviour | one diagnostic for most cases; I12 reports a single inserted-token message |
| structured data | token text/type and span yes; expected set text-only |
| multi-error | yes, listener receives each diagnostic |
| formatted (<=50 LOC) | "1:17: expected ']' to close the observation expression, found 'FALLOWEDBY'." |

## 5. Cost

| implementation | PoC LOC | direct deps | dep tree lines | rebuild | generated source | debug binary | MSRV |
|---|---|---|---|---|---|---|---|
| antlr | 178 (168 runner + 10 build.rs) | 3 | 30 | 8 s | 314 KB | 28 MB | 1.95 |

The grammar compiled unmodified; no lexer/parser split was required.

## 6. Verdict

Pending the remaining front ends and the winner spike.
