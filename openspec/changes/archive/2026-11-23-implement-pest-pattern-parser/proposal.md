# Proposal

## Why

The archived evaluation (`2026-11-18-evaluate-pattern-parsers`) showed that the shipped nom front end
is incomplete and position-less: it rejects at least 20 grammar-valid patterns (including five of the
reference validator's 23 `spec_examples.txt` cases), accepts three invalid ones, and reports the whole
pattern with no column. The evaluation selected pest as the front end and proved that an extended AST
can represent and check all 51 must-pass patterns. This change adopts that result.

The existing pattern fixtures under `testdata/stix/{valid,invalid}/patterns/` are not referenced by any
test, and one "valid" fixture (`EXISTS [file:name]`) is actually invalid. The suite therefore cannot
protect the behavior this change alters. Fixing that is part of the work, not a follow-up.

## What Changes

- Replace the nom front end in `rust/src/pattern/mod.rs` with a hand-ported pest grammar
  (`pest` + `pest_derive`) covering the full 237-line STIXPattern grammar: keywords, operators,
  literals, comments, the Unicode whitespace set, qualifiers, `NOT` placement, and parenthesised
  groups.
- Extend `rust/src/pattern/expr.rs`: add `negated` to `ComparisonExpression`, change
  `BooleanOp`'s right-hand side to a `ComparisonComponent`, and move the `REPEATS > 0` /
  `WITHIN > 0` / `START < STOP` rules into `stix_check` so every front end enforces them.
- Produce plain-language diagnostics with line/column, expected constructs, and the offending token;
  keep `ValidationError` with the `invalid_pattern` entry and never expose parser internals.
- Turn the pattern fixtures into a consumed, language-agnostic JSON corpus. Keep the existing
  `testdata/stix/{valid,invalid}/patterns/` layout, standardise each file on
  `{description, pattern, spec}` (plus an expected-error note for invalid cases), correct the invalid
  `EXISTS` case, and promote the evaluation's 77 cases.
- Wire the fixtures into both the Rust and Python test suites, and add a grammar-coverage check that
  maps every parser rule to at least one case.
- Confirm the parser is pure Rust and shippable: no `build.rs`, no external generator, no JVM, and no
  runtime files, so the extension and future bindings inherit it as-is.
- Treat the STIX 2.1 specification as authoritative where the reference validator differs, and
  document known reference drifts in `README.md`.
- **BREAKING (Rust API):** adding a field to the public `ComparisonExpression` and changing
  `BooleanOp`'s right-hand side breaks direct constructors. The Python API is unchanged.

## Capabilities

### New Capabilities

- `stix-pattern-validation`: accepting the full STIX 2.1 patterning grammar, preserving pattern
  structure so semantic checks can run, enforcing the pattern semantic rules, producing positional
  diagnostics, and guaranteeing language-agnostic fixture coverage.

### Modified Capabilities

- `error-reporting`: the pattern-parse requirement gains position and expected-construct detail while
  keeping the plain-language, no-internals bar.

## Impact

- Code: `rust/src/pattern/mod.rs`, `rust/src/pattern/expr.rs`, `rust/src/pattern/util.rs` (removed if
  unused), `rust/src/error/`, and `rust/src/python_bindings/functions.rs` (no signature change).
- Fixtures and tests: `testdata/stix/{valid,invalid}/patterns/`, `rust/tests/`, `tests/`.
- Dependencies: add `pest` and `pest_derive`; remove `nom` and `nom-language`, which are used only by
  the replaced pattern module.
- Python API: unchanged. Error messages become more specific, and previously rejected valid patterns
  now validate.
