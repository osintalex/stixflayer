# Tasks

## 1. Fixture corpus

- [ ] 1.1 Convert `testdata/stix/valid/patterns/*.json` to arrays of
  `{id,description,pattern,spec}`, and correct the invalid `EXISTS [file:name]` entry to
  `[EXISTS file:name]`; verify a `fixture_schema` test accepts every entry and rejects duplicate IDs.
- [ ] 1.2 Convert `testdata/stix/invalid/patterns/*.json` to arrays of
  `{id,description,pattern,spec,layer,expected_error}`, where `layer` is `grammar` or `semantic`;
  verify the schema test requires both fields and rejects an unknown `layer`.
- [ ] 1.3 Promote the evaluation's 77 cases and all 23 `spec_examples.txt` lines into the fixture
  files with spec anchors, plus the compliance cases (`REPEATS 0` and `WITHIN 0` invalid at the
  semantic layer, reversed or equal `START`/`STOP` valid); verify every ID is unique, every entry has
  a `spec`, the valid set contains all 23 specification examples, and each compliance case declares
  the correct layer.

## 2. AST and semantics

- [ ] 2.1 Add `negated` to `ComparisonExpression` and change `BooleanOp`'s right-hand side to
  `Box<ComparisonComponent>`; update the existing nom constructors (`negated: false`, rhs wrapped in a
  component) so the crate still compiles; verify `cargo test -p stixflayer` passes and AST unit tests
  cover negation and groups.
- [ ] 2.2 Update `stix_check` and `get_matching_object` to recurse on both sides of `BooleanOp`, and
  move `REPEATS > 0` and `WITHIN > 0` into the semantic layer; verify unit tests reject zero ranges,
  AND across SCO types, duplicate qualifiers, and operator/literal mismatches, and accept reversed or
  equal `START`/`STOP` ranges.

## 3. Pest front end

- [ ] 3.1 Add `rust/src/pattern/stix.pest` with the upstream grammar SHA in its header, and implement
  the pest parser module; verify it parses every valid fixture through a unit test.
- [ ] 3.2 Map pest diagnostics to `line:column: expected …, found …` with rule-name phrases and no
  parser internals; verify snapshot tests for `I01`, `I04`, `I06`, `I12`, `I13`, and `I25` and the
  `error-reporting` assertions.
- [ ] 3.3 Switch `validate_pattern` to the pest front end and remove the nom parser path; verify
  `cargo test -p stixflayer` and the existing Python pattern tests pass.

## 4. Fixture consumers and coverage

- [ ] 4.1 Add `rust/tests/pattern_fixtures.rs` reading both fixture directories; verify valid entries
  are accepted, invalid entries fail at the declared layer, and `expected_error` appears in the
  message.
- [ ] 4.2 Add `tests/test_pattern_fixtures.py` with the same assertions through
  `stixflayer.validate_pattern`; verify `pytest tests/test_pattern_fixtures.py` passes.
- [ ] 4.3 Add `testdata/stix/pattern_coverage.json` and a test that walks every parser `Rule` and
  fails when a rule has no case; verify a deliberately uncovered rule makes the test fail and the
  full map passes.

## 5. Portability and cleanup

- [ ] 5.1 Remove `nom`, `nom-language`, and `rust/src/pattern/util.rs`; verify `cargo tree -p
  stixflayer` contains neither nom crate and the workspace still builds.
- [ ] 5.2 Update `docs/guides/patterns.md` for the new message shape and add a "Known divergences from
  the reference validator" section to `README.md` covering zero qualifiers, the hash inspector, the
  bracket pre-scan, the `[-1]` crash, and the reversed `START`/`STOP` policy; verify the documented
  example runs as written and the section lists each drift.

## 6. Verification

- [ ] 6.1 Run the full Rust and Python suites; verify zero failures.
- [ ] 6.2 Add a non-gating parity script comparing verdicts with `stix2patterns`; verify it runs and
  lists the known divergences (qualifier ranges, hash inspector, bracket pre-scan).
- [ ] 6.3 Confirm no unrelated files changed; verify with `git diff --stat`.

## Workflow follow-up

- Archive the change with `/opsx-archive` once review is complete.
- Reuse `testdata/stix/{valid,invalid}/patterns/` from future language bindings without translating
  the fixtures.
