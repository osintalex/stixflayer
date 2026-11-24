# Tasks

## 1. Positioning and README

- [x] 1.1 Write the positioning sentence once ("the fastest, most spec-correct STIX 2.1 library for Python, powered by a Rust engine, with a native CLI") and use it verbatim in the README tagline, `mkdocs.yml` `site_description`, and the `docs/index.md` introduction; verify the three strings match by inspection.
- [x] 1.2 Rewrite `README.md` to the eight-section skeleton in design.md D2 and verify `wc -l README.md` is 100 or fewer while the file still contains `pip install stixflayer` and the CLI install command.
- [x] 1.3 Delete the language status table and every TypeScript, JavaScript, Go, Java, WASM, Extism, and napi reference from `README.md`, `docs/`, and `mkdocs.yml`; verify a case-insensitive grep over those paths returns no matches presenting them as shipped or planned bindings.
- [x] 1.4 Replace the README spec-conformance bullet list with a link to the conformance page; verify no individual spec finding remains in the README and the link target exists after task 3.1.
- [x] 1.5 Replace the README performance table with the two rows from `benchmarks/BENCHMARKING.md` (apt1 and poisonivy, parse + validate) and verify each quoted speedup equals the ratio of the numbers in that file.

## 2. Registry-specific READMEs and metadata

- [x] 2.1 Add `rust/README.md` with `cargo add stixflayer`, a minimal parse example, the crate's validation model, and a pointer to the CLI crate; change `rust/Cargo.toml` to `readme = "README.md"` and verify `cargo package --list` from `rust/` includes the new README.
- [x] 2.2 Verify `rust/README.md` examples compile by adding them as a doc test or running them against the crate, and verify the page does not present Python as the only interface.
- [x] 2.3 Rewrite the `pyproject.toml` and `rust/Cargo.toml` descriptions as one audience-appropriate sentence each; verify neither mentions other-language support and both match the positioning sentence's claims.

## 3. Conformance page

- [x] 3.1 Create `docs/guides/conformance.md` containing the existing spec-conformance notes moved from the README, each with its spec basis, plus a "tested against public feeds" section covering Amnesty, MVT, and MITRE ATT&CK; verify every claim is backed by a fixture, test, or the manual check recorded in `fix-validation-correctness`.
- [x] 3.2 Link the conformance page from the README and from `docs/guides/validation.md`; verify both links resolve in the built site.

## 4. Docs site

- [x] 4.1 Rewrite `docs/index.md` with the positioning sentence, cards for Quickstart, Guides, API reference, CLI, and the Rust crate, and no "consumed by many languages" or "10–40×" claim; verify every card link resolves.
- [x] 4.2 Add the CLI install and a one-command validation example with its exit-code meaning to `docs/quickstart.md`, keeping the existing Python examples; verify the Python blocks still carry their `#>` markers.
- [x] 4.3 Update `mkdocs.yml` `site_description` and add `Conformance` under Guides in the nav (leave the CLI nav entry to `add-validation-cli`); verify the site builds.
- [x] 4.4 Sweep `docs/guides/validation.md`, `docs/guides/parsing.md`, and `docs/guides/errors.md` for polyglot wording and outdated install instructions, and verify each page's claims against the current CLI and library behaviour.

## 5. Documentation verification

- [x] 5.1 Run `uv run pytest tests/test_docs_examples.py` and verify every edited Python block still executes with its documented output.
- [x] 5.2 Build the site with the pinned tooling (`zensical build --clean` from a venv created from `docs/requirements.txt`) and verify it succeeds with no broken-link warnings.
- [x] 5.3 Verify `README.md` and `rust/README.md` do not contradict each other on version, install commands, or positioning.

## 6. Integration verification

- [x] 6.1 Run `uv run ruff check .`, `uv run pyrefly check`, and `uv run pytest`; verify all pass.
- [x] 6.2 Verify the README's CLI example runs as written once `add-validation-cli` is applied, and record in the review notes that the example depends on that change.

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- Verify the published crates.io page renders `rust/README.md` after the next Rust release.
