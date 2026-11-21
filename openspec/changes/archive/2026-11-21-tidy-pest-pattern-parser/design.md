# Design

## Context

See `proposal.md` - Why. The branch already replaced the nom front end with
pest (`rust/src/pattern/stix.pest`, `rust/src/pattern/mod.rs`). What remains is
exploration and test scaffolding:

- `poc-parser/` is a separate Cargo workspace (48 tracked files) from the parser
  evaluation. The only live reference outside it is
  `rust/tests/pattern_fixtures.rs`, which reads
  `poc-parser/corpus/spec_examples.txt`.
- The 23 specification examples are already duplicated in
  `testdata/stix/valid/patterns/spec-examples.json` (V01–V23, `spec: "9.8"`).
- `scripts/pattern_parity.py` is a non-gating diagnostic added by the parser
  change. It is not run by CI and duplicates the README divergence list; the two
  lists have already drifted (`I29` is missing from the README, while the
  README's `START`/`STOP` item is not a current `stix2patterns` divergence).
- The shared corpus has two consumers by design: `rust/tests/pattern_fixtures.rs`
  and `tests/test_pattern_fixtures.py`. Both must stay.
- No spec-level behavior changes, so the change sets `skip_specs: true`.

## Goals / Non-Goals

**Goals:**

- Leave one canonical location for pattern data (`testdata/stix/`), one for the
  parser decision (the pest grammar header), and one for known divergences
  (`README.md`).
- Reduce the Rust pattern test surface to the tests that prove distinct
  behavior, without weakening the Rust/Python corpus contract.
- Land the work as two reviewable commits: PoC removal, then test/docs tidy.

**Non-Goals:**

- Changing parser behavior, diagnostics, the public API, or dependencies.
- Reworking the fixture schema, IDs, or the grammar-coverage mechanism.
- Adding CI gating for reference-validator parity.
- Rewriting archived OpenSpec changes that mention `poc-parser/`.

## Decisions

### D1. Delete `poc-parser/` wholesale, including `RESULTS.md`

Remove the workspace, its corpus, harnesses, snapshots, and `RESULTS.md`.
Delete `valid_set_contains_all_spec_examples` with it instead of relocating
`spec_examples.txt`: the same 23 examples already exist in
`testdata/stix/valid/patterns/spec-examples.json`, so the test only compared
two copies of one list.

Alternatives: keep `RESULTS.md` under `docs/`; move `spec_examples.txt` into
`testdata/`. Both preserve duplication for no behavioral gain. The parser
rationale moves into the grammar header (D2), and the archived
`2026-11-18-evaluate-pattern-parsers` change remains the historical record even
though its `poc-parser/` paths no longer resolve.

### D2. Put the five-line parser rationale in `stix.pest`

Add a short comment to `rust/src/pattern/stix.pest` beside the existing upstream
grammar provenance: antlr-rust needs a generator and a newer MSRV, chumsky leaks
trivia into expected sets, nom discards the deepest error, and `pest_derive` is a
proc macro with no external toolchain whose expected-token sets produce the
required diagnostics.

Alternatives: `mod.rs` module docs, a standalone ADR, or keeping `RESULTS.md`.
The grammar file is where a future maintainer asks "why this grammar?", and the
comment is cheaper than a document that can drift.

### D3. Delete `scripts/pattern_parity.py`; README is the only divergence list

The script is not run in CI, duplicates `KNOWN_DIVERGENCES` against the README,
and depends on `stix2-patterns` only transitively through the dev-only
`stix2-validator` dependency. Keeping it means maintaining two lists that
already disagree.

Alternatives: keep it as a documented diagnostic; promote it to a CI gate with a
pinned reference version. A gate adds a moving external oracle to CI, and a
diagnostic nobody runs has already rotted. Delete it.

### D4. Keep both corpus consumers; trim only the Rust meta-tests

The JSON corpus is the cross-language contract, so the Rust integration test and
the Python integration test both stay. Trim `rust/tests/pattern_fixtures.rs` to:

1. `fixture_schema_accepts_corpus` — one schema gate.
2. `valid_fixtures_are_accepted` — valid corpus through `validate_pattern`.
3. `invalid_fixtures_fail_at_the_declared_layer` — layer and message contract.

Delete `fixture_schema_rejects_duplicate_ids`,
`fixture_schema_rejects_unknown_layer`, and
`fixture_schema_requires_layer_and_expected_error` (they test the test helper),
`compliance_cases_declare_the_expected_layer` (duplicates schema plus
conformance and contains two identical loops), and
`valid_set_contains_all_spec_examples` (D1).

In `rust/src/pattern/mod.rs`, delete `every_valid_fixture_parses`: the
integration test already proves the same corpus through the public API. Keep the
coverage-map test, the diagnostics snapshots, and the parser-level failure-shape
test.

Alternatives: keep the meta-tests for confidence in the helper. They do not
exercise product behavior, and the schema gate plus serde already covers the
deserialization contract.

### D5. Drop the hard-coded fixture counts

Replace `assert_eq!(valid.len(), 64)` and `assert_eq!(invalid.len(), 34)` with a
non-empty assertion. Exact counts force an edit for every fixture addition and
add no behavioral signal; deleting a whole fixture file is visible in review.

Alternative: keep the counts as a deletion alarm. The churn cost outweighs the
one failure mode it catches.

### D6. Make V54 a normal hash fixture

V54 in `testdata/stix/valid/patterns/basic.json` is a 63-character SHA-256
described as "Simple file hash equality". It passes only because pattern
validation does not inspect hash formats, which V46 already tests explicitly.
Replace V54's value with a valid 64-character SHA-256 so `basic.json` contains a
normal pattern.

Alternative: keep the short value and change the description. That leaves two
hash-inspection fixtures and makes the "normal" corpus file look wrong.

### D7. Name the reference chain and complete the README divergence list

Rewrite the README introduction to state that `cti-stix-validator`
(`stix2-validator`) validates patterns with `stix2-patterns` (import name
`stix2patterns`, source `oasis-open/cti-pattern-validator`), link that
repository, and add the missing custom-SCO-type divergence (`I29`). Keep the
existing zero-qualifier, hash-inspection, block-comment, negative-index, and
`START`/`STOP` entries.

Alternatives: leave the name unlinked; point to the archived PoC for context.
Both keep the reader guessing what `stix2patterns` is, and the PoC is being
removed.

### D8. Two commits

Commit 1 removes `poc-parser/` and the test that reads it. Commit 2 trims the
tests, adds the grammar comment, deletes the parity script, and updates the
README and V54. Each commit should leave the Rust and Python suites green.

Alternative: one commit. The first change is mechanical and large; separating it
keeps the judgment calls in the second commit reviewable.

## Risks / Trade-offs

- **The parser-choice evidence disappears with `RESULTS.md`** -> The grammar
  header records the decision and the archived evaluation remains in OpenSpec;
  the detail is not needed to maintain the parser.
- **Trimming tests hides a regression** -> The corpus conformance tests,
  grammar-coverage map, diagnostics snapshots, AST-shape tests, and Python
  conformance all remain; only meta-tests and one duplicate disappear.
- **The README divergence list can still rot** -> It becomes the single owner,
  so a behavior change has one place to update; there is no second list to
  disagree with it.
- **V54 no longer exercises hash-format leniency** -> V46 keeps that case
  explicit.
- **A future reader looks for `poc-parser/` from an archived change** -> The
  archive is historical; the grammar header is the current explanation.

## Migration Plan

1. Commit 1: delete `poc-parser/`; remove `valid_set_contains_all_spec_examples`;
   run `cargo test` in `rust/`.
2. Commit 2: trim `rust/tests/pattern_fixtures.rs`, remove
   `every_valid_fixture_parses`, add the `stix.pest` comment, delete
   `scripts/pattern_parity.py`, update `README.md` and V54; run the Rust and
   Python quality gates.
3. Rollback: revert either commit. No runtime behavior, public API, or
   dependency changes are involved.

## Open Questions

None.
