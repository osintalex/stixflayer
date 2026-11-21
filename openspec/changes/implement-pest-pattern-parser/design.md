# Design

## Context

See `proposal.md` - Why. Current state that shapes the approach:

- `rust/src/pattern/mod.rs` and `util.rs` hold a nom front end; `expr.rs` holds the AST and the
  `stix_check` semantic layer. `pub mod pattern` and `pub mod expr` are public; the crate is 0.1.0.
- `validate_pattern` maps parse failure to `StixError::ParsePatternError`, which the Python binding
  raises as `ValidationError` with an `invalid_pattern` entry (`error-reporting`).
- `testdata/stix/{valid,invalid}/patterns/` exists but nothing reads it, and the "valid"
  `EXISTS [file:name]` entry is grammar-invalid.
- The archived evaluation (`2026-11-18-evaluate-pattern-parsers`, `poc-parser/RESULTS.md`) measured
  pest at 51/51 must-pass, proved the AST extension with a mirror at 51/51, and rejected antlr,
  chumsky, and a nom rewrite on diagnostics and cost.
- Constraints: pure Rust, no external generator or JVM, usable from every binding, Python API
  unchanged, CI on stable Rust.

## Goals / Non-Goals

**Goals**

- One front end that accepts the full grammar and feeds the existing semantic layer faithfully.
- Diagnostics that satisfy the `error-reporting` bar with position and expected construct.
- A fixture corpus that is language-agnostic, consumed by Rust and Python, and provably covers the
  grammar.
- A build that needs only the Rust toolchain and links into every binding.

**Non-Goals**

- Evaluating patterns against observations.
- Replicating the reference validator's inspector checks (hash formats, bracket pre-scan), which are
  outside the grammar and conflict with it in places.
- Changing the Python API or adding new public Python functions.
- Keeping nom for anything other than the pattern module; it has no other user.

## Decisions

### D1. pest with a hand-ported grammar

Use `pest` 2.9 and `pest_derive` 2.9, with the grammar at `rust/src/pattern/stix.pest`. The file
header records the upstream `STIXPattern.g4` SHA-256 so drift is detectable.

Alternatives: antlr-rust (codegen crate, MSRV 1.95, `libc` pin, and its expected sets do not contain
the operator alternatives — `RESULTS.md` section 2.1); chumsky (trivia leaks into every expected set
and keywords fail mid-token); a fresh nom parser (`alt` discards the deepest error). pest was the only
candidate whose expected set contained `FOLLOWEDBY` for the outer typo case.

Portability: `pest_derive` is a proc macro compiled by `rustc`; there is no `build.rs`, no generator
binary, no JVM, and no runtime data file. The parser is statically linked, so the pyo3 extension and
future bindings inherit it with no extra toolchain. MSRV is 1.88.

### D2. Extend the AST rather than normalise patterns

`ComparisonExpression` gains `negated: bool`; `BooleanOp`'s right-hand side becomes
`Box<ComparisonComponent>`.

Alternatives: rewrite `NOT =` to `!=` (rejected: not equivalent for `NOT IN`, `NOT LIKE`,
`NOT EXISTS`, and it discards what the user wrote); drop `NOT` during validation (the same lossiness
as mapping `LIKE` to `=`); introduce a separate `Negated` enum (more churn for the same result).
`stix_check` recurses on both sides of `BooleanOp`, and `get_matching_object` compares both sides.

This is a breaking change to public Rust types. The crate is 0.1.0, the Python API does not expose the
AST, and every constructor is in this repository.

### D3. Qualifier rules follow the specification

`REPEATS > 0` and `WITHIN > 0` move into `stix_check`: the specification says "positive integer" and
"positive floating-point or integer value", so zero is invalid. The reference validator accepts zero;
that is a reference drift, and the specification wins.

`START`/`STOP` is different. The specification defines the matched range as `x <= observation < y` but
does not prohibit `x >= y`, so the validator must **not** reject a reversed or equal range. The
previous parser did reject it; that check is removed as stricter than the specification.

Alternatives: keep the checks in the front end (every front end must reimplement them); follow the
reference (contradicts the specification on zero); keep rejecting reversed ranges (stricter than the
specification). Known reference drifts — zero qualifiers, the hash inspector, the bracket pre-scan,
and the `[-1]` crash — are documented in `README.md`.

### D4. Keep the fixture directories, standardise the entries

Retain `testdata/stix/valid/patterns/` and `testdata/stix/invalid/patterns/`. Every file becomes a JSON
array of entries:

```json
{"id":"V01","description":"...","pattern":"...","spec":"9.6.1"}
{"id":"I01","description":"...","pattern":"...","spec":"9.6.1","layer":"grammar","expected_error":"expected a value"}
```

`layer` is `grammar` or `semantic`, so a consumer knows which stage should reject. `expected_error` is
a substring assertion, not a full message, to avoid over-fitting.

Alternatives: one combined file (less discoverable); keep the invalid indicator objects (mixes
`Indicator` validation with pattern validation, and `validate_pattern` takes a string). The four
existing invalid files are converted to pattern entries; the valid `EXISTS [file:name]` is corrected
to `[EXISTS file:name]`.

The evaluation's 77 cases are promoted with their IDs, alongside all 23 `spec_examples.txt` patterns
and grammar-edge cases. Consumers: `rust/tests/pattern_fixtures.rs`,
`tests/test_pattern_fixtures.py`, and any future binding.

### D5. Enforce grammar coverage mechanically

`testdata/stix/pattern_coverage.json` maps each parser rule name to the fixture IDs that exercise it.
A test walks every `Rule` variant through a `rule_name(Rule) -> &'static str` function and fails if a
rule has no case. A second check fails if a valid fixture lacks a `spec` anchor.

Alternatives: rely on corpus size (weak), manual review (not enforced). The mapping is manual but the
completeness check is mechanical.

### D6. Map pest errors to product messages

`ErrorVariant::ParsingError` supplies `positives`/`negatives` as `Rule` sets; map them to phrases
(`kw_and` → `'AND'`, `primitive_literal` → "a value (number, string, timestamp, …)"), dedupe, and emit
`line:column: expected …, found …`. `CustomError` passes through. Keep `ParsePatternError` and the
Python `invalid_pattern` entry.

Alternatives: raw pest rendering (rule names and snippets leak internals); a generic "syntax error"
(loses the expected construct). Snapshot tests cover `I01`, `I04`, `I06`, `I12`, `I13`, `I25`, and the
spec examples.

### D7. Remove nom and nom-language

They are used only by `rust/src/pattern/`. Remove both dependencies and `util.rs` once the pest front
end is in place. Verify with a grep before removal.

### D8. Test layers

1. **Fixture conformance** — Rust and Python both read the JSON corpus; valid entries must succeed,
   invalid entries must fail at the declared layer, and `expected_error` must appear in the message.
2. **Grammar coverage** — D5.
3. **AST shape** — negation preserved, groups on both sides, left-associative chains, qualifier
   nesting, flattened object paths, lossless `Like`/`Hex`/`Binary`/`Neq`.
4. **Semantics** — `AND` across SCO types, duplicate qualifiers, ranges, operator/literal
   compatibility, invalid object paths.
5. **Diagnostics** — position present, expected construct named, no debug structs, parser error kinds,
   or `crate::` paths.
6. **Build** — a clean `cargo build` and the Python extension build are part of the acceptance run.
7. **Optional parity report** — a non-gating script compares verdicts with `stix2patterns` and lists
   known divergences (qualifier ranges, hash inspector, bracket pre-scan). It is a diagnostic, not an
   oracle.

## Risks / Trade-offs

- **Hand-ported grammar drifts from the `.g4`** → grammar SHA in the file header, the 23 spec
  examples, and the coverage check; a future grammar update starts by diffing the header.
- **Diagnostics regress during the port** → snapshot tests on the showcase cases and the
  `error-reporting` assertions.
- **Breaking AST change ripples through constructors** → contained in this repository; update all
  construction sites in the same change; document the break.
- **Fixtures become stale or unused** → one schema, two consumers, and the coverage check; a fixture
  that no test reads is itself a failure.
- **Binary size grows** → measure release delta; pest is small (debug PoC binary was 6.8 MB with the
  harness included).
- **Reference divergence is mistaken for a bug** → fixtures record `layer` and `spec`, and the parity
  report lists known differences.

## Migration Plan

1. Convert and extend the fixtures, add the coverage map, and wire the Rust and Python consumers. This
   lands red: the current parser fails the new valid cases.
2. Extend `expr.rs` and `stix_check`, with AST and semantic unit tests.
3. Add the pest grammar and module, map diagnostics, and switch `validate_pattern`.
4. Remove nom/nom-language and `util.rs`; update `docs/guides/patterns.md` for the new message shape.
5. Run the Rust suite, the Python suite, and the extension build.

Rollback: revert the change. The Python API is unchanged, so callers are unaffected either way.

## Open Questions

None that change the specs, approach, or task breakdown. The qualifier policy is decided in D3: the
specification wins, and reference drifts are documented in `README.md`.
