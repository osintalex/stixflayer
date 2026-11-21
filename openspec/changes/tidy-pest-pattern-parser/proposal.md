# Proposal

## Why

The pest pattern parser is ready, but the branch still carries the throwaway
parser-evaluation workspace, a diagnostic script that no CI runs, and test and
README layers that duplicate each other. Before this branch merges to `main`,
the exploration scaffolding should be removed and the surviving test and
documentation surface should be small enough to maintain.

## What Changes

- Remove the entire `poc-parser/` workspace, including `RESULTS.md`, the
  comparison harnesses, corpus, and result snapshots.
- Delete `valid_set_contains_all_spec_examples`, the only test that reads
  `poc-parser/corpus/spec_examples.txt`. The 23 specification examples already
  live in `testdata/stix/valid/patterns/spec-examples.json` (V01–V23).
- Record the parser decision as a five-line comment in the pest grammar header:
  why pest was chosen over antlr-rust, chumsky, and a nom rewrite.
- Delete `scripts/pattern_parity.py`. Known divergences from the reference
  validator live only in `README.md`; no second list is maintained.
- Trim `rust/tests/pattern_fixtures.rs` to the two conformance tests plus one
  schema gate. Remove the three tests that exercise the test helper, the
  duplicate compliance-data assertion, and the hard-coded fixture counts.
- Remove `every_valid_fixture_parses` from `rust/src/pattern/mod.rs`; the
  integration test already proves the same corpus through the public API.
- Rewrite the README's known-divergences introduction to name the reference
  chain explicitly: `cti-stix-validator` (`stix2-validator`) validates patterns
  with `stix2-patterns` (import name `stix2patterns`, source
  `oasis-open/cti-pattern-validator`). Link that repository, add the missing
  custom-SCO divergence (`I29`), and make V54 a normal 64-character SHA-256
  fixture instead of a second hash-inspection case.

No validation behavior, public API, or dependency changes. The work lands as
two commits: one removing the PoC, one tidying tests and documentation.

## Capabilities

### New Capabilities

None. This is a pure cleanup of exploration scaffolding, tests, and
documentation; no spec-level behavior changes.

### Modified Capabilities

None.

## Impact

- Removes 48 tracked files under `poc-parser/` and deletes
  `scripts/pattern_parity.py`.
- Touches `rust/tests/pattern_fixtures.rs`, `rust/src/pattern/mod.rs`,
  `rust/src/pattern/stix.pest`, `README.md`, and
  `testdata/stix/valid/patterns/basic.json`.
- `rust/Cargo.toml`, `rust/Cargo.lock`, and the Python package are unchanged:
  `poc-parser/` is a separate workspace, and pest remains the parser.
- No public API or validation behavior changes.
