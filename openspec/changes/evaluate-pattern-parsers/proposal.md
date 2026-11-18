# Proposal

## Why

`stixflayer.validate_pattern` is the Python-facing validator for `Indicator.pattern`, and its current
front end (`rust/src/pattern/mod.rs`, nom) is both incomplete and position-less. Against the official
STIXPattern grammar it rejects at least fourteen valid constructs — `>=`/`<=`, `START`/`STOP`, `==`,
`<>`, empty sets, `NOT =`, `NOT EXISTS`, `b'...'`, `//` and `/* */` comments, non-breaking-space
whitespace, escaped quotes, and `[file:name='x']` without spaces — while accepting the grammar-invalid
`[file:size = 007]`. Every failure reports the whole pattern and no column, e.g.
`expected a specific character near '[file:name = ]'`.

The obvious quality bar, the reference `stix2patterns` validator, does not rescue this: it reports
`[file:created = t'2025-13-01T00:00:00Z']` as `extraneous input 't' expecting {IntNegLiteral, ...}`
(never mentioning the invalid month), and it crashes on the grammar-valid `[-1]` path index. Neither
the status quo nor the reference is a usable target, so a Rust front end has to be chosen on evidence.

The comparison brief's prior lean toward `antlr-rust-runtime` rests on "computed expected sets enable
did-you-mean suggestions". The official ANTLR build of the same grammar already refutes that for the
flagship case: `[file:name = 'x' FALLOWEDBY ...]` yields `mismatched input 'FALLOWEDBY' expecting ']'`
— the expected set is `{']'}`, not `FOLLOWEDBY`. That hypothesis must be tested before hours are spent
on it.

## What Changes

- Add a throwaway `poc-parser/` Cargo workspace, independent of the `rust/` workspace, with a shared
  harness, four front-end PoCs (nom 8, pest 2, antlr-rust 0.34, chumsky 0.14), and a fifth baseline
  member that runs the shipped `validate_pattern`.
- Replace the brief's line-based corpus with JSONL, so patterns may contain `/* */` and `//`, and so
  expected verdicts carry a `basis` field (`grammar`, `reference`, `spec`, `shipped`) instead of
  living in prose.
- Extend the corpus with the valid constructs the current parser rejects, the reference validator's
  bug cases, and all 23 lines of `spec_examples.txt`. Flag grammar-versus-semantics cases
  (`REPEATS 0`, `WITHIN 0`, `AND` across SCO types) so they are not scored against grammar-only
  front ends.
- Score each front end twice per case: raw library output, and the best message reachable with a
  small formatter (<=50 LOC), because the product needs plain language that satisfies the
  `error-reporting` spec.
- Record cost evidence the brief omits: LOC, dependency count, compile time, generated-source size,
  binary delta, MSRV (antlr 0.34 requires 1.95), and grammar-drift risk.
- Run the antlr hypothesis as a gate before the remaining PoCs, then run a winner spike that builds
  the existing `stixflayer::pattern::expr` AST and calls `stix_check()` without editing `rust/`.
- Deliver `poc-parser/RESULTS.md` with verbatim showcases, a correctness matrix, a diagnostics
  assessment, a cost table, and a verdict with a documented fallback.
- **No product behavior change.** Adoption of the chosen front end is a separate change, proposed
  after `RESULTS.md` exists.
- **Out of scope:** semantic-layer changes, new error kinds, Python API changes, and any edit under
  `rust/`, `src/`, `tests/`, or `testdata/`.
- The execution runbook (phases, gates, corpus schema, harness contract) is captured in
  `design.md` and `tasks.md`, not in a separate `PLAN.md`.

## Capabilities

### New Capabilities

- None. This change produces evidence and a recommendation; it does not alter observable behavior.

### Modified Capabilities

- None. The `error-reporting` requirement for pattern messages is exercised by the PoC's formatting
  column but not changed here. The follow-up adoption change will introduce a pattern-validation
  capability and amend `error-reporting`.

## Impact

- Code: new `poc-parser/` workspace only. `rust/`, `src/`, `tests/`, `testdata/`, and the Python API
  are untouched.
- Specs: none changed (`skip_specs: true`). The verdict constrains the follow-up change that will
  replace `rust/src/pattern/mod.rs`.
- Dependencies: `nom`, `pest`, `antlr-rust-runtime`, `antlr-rust-codegen`, and `chumsky` appear only
  inside `poc-parser/`'s own lockfile; `rust/Cargo.toml` is unchanged.
- Process: the brief said "do not commit, leave untracked". This change overrides that — work lands
  in incremental commits on `poc-parser-exploration` so progress is reviewable, and `poc-parser/` is
  committed rather than ignored.
