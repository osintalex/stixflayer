# Design

## Context

See proposal.md for motivation. Relevant current state:

- Release pipeline (`release.yml`) already gates on version bumps, builds wheels, publishes to PyPI/crates.io, and tags `py-v*` / `rust-v*` — the natural hook points for versioned doc deploys.
- docs.rs already builds both crates successfully; the gaps are content quality (57% coverage, 0 examples, WIP crate intro, broken `#stixflayer` heading) and exposed internals.
- A one-off measurement with `missing_docs` enabled counts **804 undocumented public items**; ~56 sit in `python_bindings`, the largest clusters being `domain_objects/vocab.rs` (149), `error/mod.rs` (60), `sco/builder.rs` (59), `cyber_observable_objects/vocab.rs` (52), `taxonomy.rs` (43).
- Python floor is 3.11; CI already builds the wheel (maturin) and runs pytest/ruff.
- Zensical (the Material successor) requires Python 3.11+ and reads `mkdocs.yml`; a Zensical-compatible fork of `mike` provides versioned GitHub Pages deploys.

## Goals / Non-Goals

**Goals:**

- A live, versioned, Python-facing docs site with concise curated content and a working getting-started path.
- A CI-enforced rule that no documentation example exists without compiling and running (Python + Rust).
- docs.rs pages for both crates that present an accurate, fully documented, example-backed Rust API.

**Non-Goals:**

- Custom domain, analytics, Algolia search (built-in search suffices at this size).
- Auto-generated API reference from docstrings (curated pages instead; revisit if docstrings mature).
- Backporting doc fixes to old published versions (fix forward in `latest`; snapshots are frozen).
- Translating the site or supporting STIX 2.0.
- A Material-for-MkDocs build canary (user decision: pin Zensical and accept the risk).

## Decisions

### D1: Site generator — Zensical, pinned exactly, no canary

Pin the exact Zensical version in the docs requirements; upgrade deliberately in dedicated PRs. Stay on the portable config subset (plain Markdown, standard extensions); avoid Material-specific template overrides so the config remains tool-agnostic.

- *Alternatives:* Material now + migrate later — rejected: it adopts a maintenance-mode stack as production and defers migration debt; the same config runs on both tools, so the fallback remains available if Zensical blocks us. Docusaurus/Sphinx — rejected: wrong ecosystem or heavier toolchain for a Python-first project.

### D2: Hosting and versioning — GitHub Pages + mike (Zensical fork)

Site URL: `https://osintalex.github.io/stixflayer/` (default Pages URL). The mike fork (installed from GitHub, transitional until Zensical native versioning) deploys to the `gh-pages` branch:

- Versions = Python **minor** releases derived from `py-v*` tags (`0.1`, `0.2`, …), not per-patch.
- `latest` alias resolves to the newest stable version; `canonical_version: latest`.
- `dev` version deploys from `main`; the root serves `latest`.

- *Alternatives:* Docusaurus-native versioning — rejected (tool choice); hand-rolled versioned directories in Actions — rejected (re-implements mike); ReadTheDocs — rejected (extra external service).

### D3: Deploy wiring — extend the existing workflows

- `release.yml`: new `docs` job with `needs: [python-publish]`; it checks out the release commit, builds the site, and runs `mike deploy <minor> latest --push`. A failed Python publish therefore never publishes a docs version.
- `ci.yml`: docs strict build + example tests on PRs; `dev` deploy on push to `main`.
- A shared `concurrency` group serializes deploys so `dev` and release deploys never interleave on `gh-pages`.

### D4: Example testing — pytest-examples

Add `pytest-examples` as a dev dependency. A `tests/test_docs_examples.py` collects examples from `docs/`, `README.md`, and Python docstrings (`src/`), then per example: lint with the project's ruff rules, execute, and verify inline printed output (pydantic-style: examples print their own output). Non-runnable blocks are excluded by using a non-Python fence language (e.g. `text`, `console`) or an explicit skip annotation — never silently. `pytest --update-examples` is the documented maintenance path for regenerating output.

CI prerequisite: the example job must build and install the compiled module (`pip install dist/*.whl` or `maturin develop`) before running the tests.

- *Alternatives:* doctest-only (`doctest` module) — rejected: no lint integration, awkward output checks; hand-maintained "expected output" comments — rejected: drifts.

### D5: Rust docs enforcement — crate-wide `deny(missing_docs)`

Enable `#![deny(missing_docs)]` in `rust/src/lib.rs`, then document the remaining ~750 public items (804 minus the hidden `python_bindings`). Scope is effectively the whole crate: the missing docs live in the user-facing modules themselves (vocab enums, error types, builders, SCOs), so a narrower "user-facing" scope would save little. `python_bindings` gets `#[doc(hidden)]`; if the lint still fires there (behavior to verify at implementation), it gets a module-level `allow(missing_docs)` since it is excluded from the user-facing docs by design.

Documentation work is batched by module family (see tasks). Doc comments follow the repo convention of linking the relevant OASIS STIX 2.1 spec sections.

- *Alternatives:* warn-only with a future deny — rejected: leaves the spec's enforcement scenario unsatisfied indefinitely; deny on a narrow module list — rejected: nearly the same work with a leaky boundary.

### D6: Crate-level docs rewrite

Fix `//! #stixflayer` → `//! # stixflayer`; replace the work-in-progress framing with an accurate introduction of released functionality; add a crate-level quick-start doctest (build a domain object via the builder, serialize it). Same treatment (minus quick-start) for `stixflayer_derive` plus per-macro docs with usage doctests.

### D7: Content model and style rules

Site structure (curated, flat, concise):

```
docs/
  index.md            what/why, install, badges, links (docs.rs for Rust)
  quickstart.md       install → parse/validate → handle error (all tested)
  guides/
    parsing.md        Bundle/Object from_json, to_json
    building.md       builders for SDOs/SCOs
    validation.md     strict vs allow_custom, structured .errors
    vocabularies.md   vocab enums, values(), is_valid
    patterns.md       validate_pattern
    errors.md         exception hierarchy + error catalog (kinds, fields)
  api/
    overview.md       curated map of the public surface
    exceptions.md     StixError/ValidationError/DeserializationError
    functions.md      version(), validate_pattern()
    domain-objects.md SDO classes (curated)
    cyber-objects.md  SCO classes (curated)
    vocabularies.md   vocab enums (curated)
```

Style rules (enforced by review, stated in contributing docs): every page answers "how do I do X" within one screen; one example per concept with real output; no filler sections (no "Overview" restating the title, no marketing prose); API pages curated to match the `.pyi` stub sections rather than dumping every member.

### D8: README refresh

Update the Languages table (published status), replace "install from source" with `pip install stixfl` / `cargo add stixfl`, link the docs site and docs.rs. README Python examples are covered by the same example tests.

## Risks / Trade-offs

- [Zensical 0.x churn (config regressions between releases)] → pin exact version; `--strict` build in CI; upgrade deliberately one PR at a time; the shared mkdocs.yml keeps a Material fallback viable. Accepted risk (user decision, no canary).
- [mike fork is transitional and GitHub-only] → isolated to one pinned dependency + deploy job; Zensical's native versioning replaces it later with the same commands.
- [Doctests link under default features (`pyo3`/`extension-module`)] → consistent with the existing `cargo test --workspace` in CI, which already passes; if linking bites, run doctests with `--no-default-features` since core-API doctests need no pyo3.
- [Example tests need the compiled module] → the CI job builds/installs the wheel first (mirrors the existing smoke-test pattern).
- [~750 doc comments is a large mechanical effort] → batched by module family across multiple PRs; vocab/variant one-liners are formulaic.
- [Versioned snapshots freeze old docs] → accepted: fixes land in `dev`/`latest` only.
- [First deploy must bootstrap `gh-pages`] → explicit bootstrap step (`mike deploy dev`) in tasks before automation is enabled.

## Implementation verification notes

Facts established while implementing (keep with the change for review):

- **`missing_docs` and `#[doc(hidden)]` (D5):** verified empirically — the lint does
  *not* fire on items inside a `doc(hidden)` module. `python_bindings` is therefore
  `#[doc(hidden)]` with every public item documented anyway; no module-level
  `allow` is needed for the crate-wide `#![deny(missing_docs)]`.
- **mike fork deploy behavior:** `mike deploy` runs `zensical build --clean`
  internally and reads `mkdocs.yml`; `set-default` in this fork writes a root
  `index.html` redirect (not the upstream `default` symlink), because GitHub
  Pages does not serve symlinks.
- **Aliases must be copies:** mike's default `--alias-type=symlink` would 404 on
  GitHub Pages (Pages does not follow symlink blobs in the served branch). The
  release job uses `--alias-type=copy`, which also keeps `latest/llms.txt` a real
  file; the site is small enough that duplicating it per release is cheap.
- **Rehearsal (local, throwaway bare remote):** the full sequence — `mike deploy
  dev --push`, conditional `set-default dev`, `mike deploy --alias-type=copy 0.1
  latest --push`, `set-default latest` — produced the expected `gh-pages` layout:
  `dev/` + `0.1/` + `latest/` (real copy of `0.1`) + `versions.json` (`dev`; `0.1`
  with alias `latest`) + root `index.html` redirect to `latest/`; `latest/llms.txt`
  served as real text.
- **Expected first-release behavior (6.3):** on merge to `main`, the `Docs`
  workflow deploys `dev` and (only if no default exists yet) points the site root
  at `dev`. The next successful Python publish then deploys the minor version
  (`0.1`) with the `latest` alias and re-points the root at `latest` — after
  that, dev deploys never touch the default. A failed or skipped Python publish
  publishes nothing: the `release.yml` docs job has `needs: [gate, python-publish]`
  and inherits the skip/failure, with no `always()` anywhere. Patch releases
  (`0.1.x`) update the same `0.1` directory.

## Migration Plan

1. Land site scaffold + CI build/example jobs (site exists, not yet announced).
2. Author content; wire example tests; land Rust docs batches.
3. Bootstrap `gh-pages` with a manual `mike deploy dev` from `main`.
4. Enable the `release.yml` docs job; the next Python release publishes version `0.1` with `latest`.
5. Update README links; announce.

Rollback: all changes are additive (new files, workflow jobs, doc comments); reverting the workflow edits stops deploys with no runtime impact on the library.

## Open Questions

- ~~Does `missing_docs` still fire on `#[doc(hidden)]` items?~~ **Resolved:** it does
  not; no module-level allow was needed (see Implementation verification notes).
- Custom domain or analytics — deferred; revisit if adoption warrants.
