# Proposal: add-documentation

## Why

The first versions of both packages are published (PyPI `stixfl` 0.1.0; crates.io `stixfl` + `stixfl_derive` 0.1.0), but there is no documentation: the README still says "docs coming soon" on all four front doors (GitHub, PyPI, crates.io, docs.rs), the docs.rs landing page describes the library as a work in progress, and 0 of 681 documented Rust items carry examples. Adoption depends on a high-quality, concise documentation site with tested examples (pydantic-style), versioned docs, and usable Rust API docs — none of which exist today.

## What Changes

- Add a Python-facing documentation website built with **Zensical** (pinned version) and hosted on **GitHub Pages**:
  - Curated, concise content only — home, quickstart, task-oriented guides (parsing/validation, building objects, validation modes, vocabularies, patterns, error handling), an error catalog, and a hand-written API reference. No auto-generated API dumps.
  - Version selector via `mike` (Zensical-compatible fork): versions track Python releases at **minor** granularity (`0.1`, `0.2`, …), `latest` alias, plus a `dev` version built from `main`.
  - Versioned deploys ride the existing release workflow: a new docs version is published only after the Python publish job succeeds.
  - Strict builds in CI (broken links fail), `llms.txt` generated.
- Enforce **tested documentation examples** (no example exists that doesn't compile and run):
  - Python: `pytest-examples` runs every Python block in docs pages, the README, and docstring examples — linting them with the project's ruff rules and verifying printed output matches what the docs show.
  - Rust: every code block in doc comments on public items runs as a doctest in CI.
- Raise the quality of the **Rust API docs on docs.rs**:
  - Rewrite the crate-level introduction (remove "work in progress" framing), fix the broken `#stixflayer` heading, add a runnable quick-start doctest.
  - Hide internal Python-binding modules from the Rust-facing docs.
  - Document the user-facing public surface and enforce it in CI (`missing_docs` on the user-facing scope).
  - Add crate-level docs and macro documentation to `stixflayer_derive`.
- Refresh the README so it reflects published status (installs from PyPI, links to the docs site and docs.rs).

## Capabilities

### New Capabilities

- `docs-site`: The public documentation website — Zensical-built, GitHub Pages-hosted, Python-facing, versioned via mike, deployed from the release pipeline, built strictly in CI, with `llms.txt`.
- `docs-examples`: Tested documentation examples — every Python example in site pages, README, and docstrings is linted, executed, and output-verified in CI; every Rust example in doc comments runs as a doctest.
- `rust-api-docs`: Rust crate documentation quality — docs.rs builds for both crates, accurate crate-level introductions, internals hidden, user-facing public surface documented and enforced, derive macros documented.

### Modified Capabilities

None — `python-api` and `error-reporting` requirements are unchanged. (Documentation describes them; it does not alter them.)

## Impact

- **New**: `docs/` content tree, site configuration (Zensical), `gh-pages` branch, `mike` fork dependency (installed from GitHub), `pytest-examples` dev dependency, docs/example CI jobs, docs deploy job in `release.yml`.
- **Modified**: `rust/src/lib.rs` and Rust doc comments across user-facing modules (`#[doc(hidden)]` on Python-binding plumbing, new doc comments, doctests), `rust/stixflayer_derive/src/lib.rs`, `README.md`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `pyproject.toml` (dev dependencies), possibly `.pyi` docstrings.
- **Not affected**: library behavior, public API surface, error-reporting semantics, release gating logic.
- Assumes the default GitHub Pages URL (`https://osintalex.github.io/stixflayer/`); a custom domain is out of scope.
