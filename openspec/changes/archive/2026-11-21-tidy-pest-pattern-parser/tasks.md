# Tasks

## 1. Remove the parser-evaluation workspace (commit 1)

- [x] 1.1 Delete `valid_set_contains_all_spec_examples` from `rust/tests/pattern_fixtures.rs` and verify `cargo test --test pattern_fixtures` in `rust/` still passes.
- [x] 1.2 Delete the entire `poc-parser/` directory, including `RESULTS.md`, and verify `grep -rn "poc-parser" --include="*.rs" --include="*.py" --include="*.toml" --include="*.yml" .` reports no matches outside `openspec/` history.
- [x] 1.3 Run `cargo test` in `rust/`, stage the deletion and test edit by name (never `git add -A`), and create commit 1 (`chore: remove parser evaluation workspace`); verify `git status` shows no unrelated changes.

## 2. Trim the Rust pattern test surface (commit 2)

- [x] 2.1 In `rust/tests/pattern_fixtures.rs`, remove `fixture_schema_rejects_duplicate_ids`, `fixture_schema_rejects_unknown_layer`, `fixture_schema_requires_layer_and_expected_error`, and `compliance_cases_declare_the_expected_layer`; verify the file still exposes the schema, valid-corpus, and invalid-corpus tests and that `cargo test --test pattern_fixtures` passes.
- [x] 2.2 Replace the hard-coded `64`/`34` fixture-count assertions with non-empty assertions, and verify `cargo test --test pattern_fixtures` passes without editing the corpus.
- [x] 2.3 Remove `every_valid_fixture_parses` from `rust/src/pattern/mod.rs`; verify `cargo test --lib pattern` still covers the coverage map, diagnostics snapshots, and parser failure shape.

## 3. Tidy documentation and fixtures

- [x] 3.1 Add the five-line pest rationale to the `rust/src/pattern/stix.pest` header beside the upstream grammar provenance, and verify `cargo test --lib pattern` still passes.
- [x] 3.2 Delete `scripts/pattern_parity.py`; verify `grep -rn "pattern_parity\|stix2patterns" --include="*.py" --include="*.md" --include="*.yml" .` reports no references outside `README.md` and `openspec/` history.
- [x] 3.3 Rewrite the README known-divergences introduction to name `cti-stix-validator` (`stix2-validator`) using `stix2-patterns` (import `stix2patterns`, source `oasis-open/cti-pattern-validator`), link `https://github.com/oasis-open/cti-pattern-validator`, and add the missing custom-SCO (`I29`) entry; verify the rendered section names the chain and every bullet matches the corpus.
- [x] 3.4 Replace V54's 63-character SHA-256 in `testdata/stix/valid/patterns/basic.json` with a valid 64-character value; verify `pytest tests/test_pattern_fixtures.py -k V54` and `cargo test --test pattern_fixtures` pass.

## 4. Verify and commit the tidy-up (commit 2)

- [x] 4.1 Run the Rust gates from `rust/`: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test`; verify all pass.
- [x] 4.2 Run the Python gates from the repository root: `uv run ruff check .`, `uv run pyrefly check`, and `uv run pytest --benchmark-disable`; verify all pass.
- [x] 4.3 Stage the test, grammar, README, fixture, and script changes by name, create commit 2 (`test: trim pattern fixtures and document reference divergences`), and verify `git log --oneline -2` shows the two intended commits with a clean working tree.

## Workflow follow-up

- Archive the change after review, following the project's archive workflow.
- Verify the archived result and confirm no root-level `design.md` or `tasks.md` was added outside `openspec/`.
