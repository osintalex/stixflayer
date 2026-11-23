# Tasks

## 1. Site scaffold and CI build

- [x] 1.1 Add pinned docs tooling (exact Zensical version; the Zensical-compatible mike fork installed from GitHub) to a docs requirements file and verify the install resolves and `zensical --version` reports the pinned version
- [x] 1.2 Create `mkdocs.yml` on the portable config subset (strict mode, `llms.txt` enabled, initial nav) plus a minimal `docs/index.md`; verify `zensical build --strict` exits 0 and `llms.txt` appears in the site output
- [x] 1.3 Add a CI job that runs the strict docs build on pull requests; verify the job passes on the PR that introduces it

## 2. Example testing infrastructure and README refresh

- [x] 2.1 Add `pytest-examples` as a dev dependency; verify it imports and `find_examples` runs over an empty docs tree
- [x] 2.2 Create `tests/test_docs_examples.py` that collects examples from `docs/`, `README.md`, and `src/` docstrings and, per example, lints with the project ruff rules, executes it, and checks inline printed output; verify `uv run pytest tests/test_docs_examples.py` passes with the initial (empty) example set
- [x] 2.3 Refresh the README to reflect published status (`pip install stixfl`, `cargo add stixfl`, docs site and docs.rs links, updated Languages table) and rewrite its Python examples to be self-contained (no external files); verify the example tests pass over the README and the strict docs build is unaffected

## 3. Documentation content

- [x] 3.1 Write `docs/quickstart.md` (install → parse and validate a document → handle a validation failure) with self-contained examples; verify example tests pass and the strict build passes
- [x] 3.2 Write `docs/guides/parsing.md` and `docs/guides/building.md` (from_json/to_json; builders for SDOs and SCOs) with tested examples; verify example tests and strict build pass
- [x] 3.3 Write `docs/guides/validation.md` (strict vs allow_custom, structured `.errors` entries) and `docs/guides/errors.md` (exception hierarchy plus error catalog of kinds and fields); verify example tests and strict build pass
- [x] 3.4 Write `docs/guides/vocabularies.md` and `docs/guides/patterns.md` (vocab enums with `values()`/`is_valid()`; `validate_pattern`) with tested examples; verify example tests and strict build pass
- [x] 3.5 Write the curated API reference pages (`docs/api/overview.md`, `exceptions.md`, `functions.md`, `domain-objects.md`, `cyber-objects.md`, `vocabularies.md`) matching the `.pyi` stub sections, with tested examples where code appears; verify example tests pass and full nav resolves in the strict build
- [x] 3.6 Finalize `docs/index.md` (what/why, install, badges, Rust-users-pointer to docs.rs); verify strict build passes and every page renders

## 4. Versioned deployment

- [x] 4.1 Add a `dev` deploy job on push to `main` (mike deploy dev) with a shared docs-deploy concurrency group, and bootstrap the `gh-pages` branch; verify the dev URL serves the site with a version selector showing `dev`
- [x] 4.2 Add the `release.yml` docs job (`needs: [python-publish]`) that builds at the release commit and runs `mike deploy <minor> latest --push`; verify the job definition with actionlint and a local rehearsal that produces the expected `gh-pages` layout (version dir + `latest` alias + root redirect)
- [x] 4.3 Rehearse the release-gate behavior: confirm the docs job does not run when `python-publish` is skipped or fails (inspect `needs` wiring with a dry-run run of the workflow graph); verify by reviewing the workflow plan output or a workflow_dispatch dry run

## 5. Rust API documentation

- [x] 5.1 Rewrite `rust/src/lib.rs` crate-level docs: fix the `#stixflayer` heading, replace work-in-progress framing with released functionality, and add a crate-level quick-start doctest; verify `cargo test --doc -p stixfl` passes
- [x] 5.2 Mark the `python_bindings` module `#[doc(hidden)]` and document the remaining public items in it; verify the rendered module list (`cargo doc`) no longer presents Python-binding plumbing as Rust user API
- [x] 5.3 Document the vocabulary enums (`domain_objects/vocab.rs`, `cyber_observable_objects/vocab.rs`) — every public item and variant, spec links per repo convention; verify `cargo rustdoc -- -W missing_docs` reports zero remaining warnings in those files
- [x] 5.4 Document the error module family (`error/mod.rs`, `error/envelope.rs`, `error/helpers.rs`, `error/classify.rs`); verify zero remaining missing-docs warnings in those files
- [x] 5.5 Document the SCO builder, SCO types, and `taxonomy.rs`; verify zero remaining missing-docs warnings in those files
- [x] 5.6 Document all remaining undocumented public items (pattern/expr, relationship types, sdo surface, datastore filters, extensions, builder, hashes, meta objects, and the rest) until `cargo rustdoc -- -W missing_docs` reports zero warnings crate-wide
- [x] 5.7 Enable `#![deny(missing_docs)]` in the crate (with a module-level allow on `python_bindings` only if the lint still fires on hidden items); verify `cargo build` and `cargo doc` succeed with the deny in place
- [x] 5.8 Write `stixfl_derive` crate-level docs and per-macro documentation with usage doctests; verify `cargo test --doc -p stixfl_derive` passes
- [x] 5.9 Add a CI job for Rust documentation: `cargo doc` build and `cargo test --doc` for both crates; verify the job passes on the PR that introduces it

## 6. Integration verification

- [x] 6.1 Run the full quality gate locally and in CI: `uv run ruff check .`, `uv run pyrefly check`, `uv run pytest` (including example tests), `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`; verify all green
- [x] 6.2 Verify the deployed dev site: version selector lists `dev`, `llms.txt` is reachable at the site root, and the getting-started path on the live pages matches the tested examples
- [x] 6.3 Confirm the release wiring end to end on paper and in rehearsal: a successful Python publish would publish docs version `0.1` with `latest` pointing to it, and a failed publish would publish nothing; record the expected first-release behavior in the change notes

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- On the next Python release, confirm the first versioned docs deploy (`0.1` + `latest`) went live and the README links resolve.
