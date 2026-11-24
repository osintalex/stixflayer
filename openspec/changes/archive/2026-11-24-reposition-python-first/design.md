# Design

## Context

See `proposal.md` — Why. Relevant current state:

- `README.md` is 232 lines and is also the crates.io landing page (`readme = "../README.md"` in `rust/Cargo.toml`).
- The docs site has 13 pages under `docs/`, a `mkdocs.yml` nav, and a portability rule: stay on the config subset shared by Zensical and Material.
- Python code blocks in `docs/` and `README.md` are executed by `tests/test_docs_examples.py` using the `#>` expected-output marker; `ruff` is excluded from Markdown to keep that harness working.
- Performance numbers appear in `README.md`, `docs/index.md`, and `benchmarks/BENCHMARKING.md`, with the poisonivy speedup quoted as both 40× and 43×.
- `ARCHITECTURE.md`, `AGENTS.md`, `POC-PARSER-COMPARISON.md`, and `stix-2.1-spec.html` are gitignored local notes and are not shipped; they are out of scope.

## Goals / Non-Goals

**Goals:**
- One sentence that describes the project, reused verbatim across entry points.
- A README that a newcomer can read in a minute and that sends them to the right place.
- Numbers that cannot contradict each other because there is one source.
- A crates.io page that serves Rust users without diluting the Python story.

**Non-Goals:**
- Rewriting the guides or API reference content beyond the pages named in the proposal.
- Changing the docs theme, plugins, or build tooling.
- Editing gitignored local notes.
- Any code or behaviour change.

## Decisions

### D1: Python-first on GitHub, Rust-first on crates.io

`rust/README.md` is added and `rust/Cargo.toml` changes `readme = "../README.md"` to `readme = "README.md"`. GitHub keeps the Python-first README; crates.io and docs.rs render a Rust-focused page with `cargo add stixflayer`, a minimal parse example, and a pointer to the CLI crate. This resolves the tension without hiding the Rust crate, which remains a marketed product.

*Alternative rejected:* one README serving both audiences. It is what exists today, and it is why the page is 232 lines and starts with a language table.

### D2: A fixed README skeleton

The README is reduced to:

1. Tagline (the positioning sentence).
2. Badges.
3. Install: `pip install stixflayer` and the CLI install.
4. Three examples: parse a bundle, catch a structured error, validate a pattern — the existing tested snippets, trimmed.
5. CLI: one command and the exit-code contract.
6. Why stixflayer: three bullets (speed, MUST/SHOULD correctness, structural completeness).
7. Links: docs, guides, conformance, CLI reference, Rust crate.
8. Credits and license.

The spec-conformance bullet list moves to `docs/guides/conformance.md` and is expanded with the real-world evidence from `fix-validation-correctness`. The line budget is enforced by review, not tooling; 100 lines is the target with the eight sections above.

### D3: `benchmarks/BENCHMARKING.md` is the only source of numbers

The README keeps a two-row table copied from the canonical file (apt1 and poisonivy, parse + validate), and the docs index quotes the same range. The 40×/43× contradiction disappears because both files quote the same two ratios. Any future number is added to `BENCHMARKING.md` first.

### D4: Conformance page structure

`docs/guides/conformance.md` contains the existing spec-conformance notes (dictionary keys, language tags, header names, qualifiers, hashes, comments, list indices, custom SCO casing, ranges) plus a short "tested against public feeds" section naming Amnesty, MVT, and ATT&CK, with what the validator accepts and where it differs from `stix2`. It is linked from the README and from the validation guide.

### D5: Docs site metadata and nav

`mkdocs.yml` `site_description` becomes the positioning sentence. The nav gains `Conformance` under Guides; the `CLI` entry is added by `add-validation-cli` when it creates `docs/cli.md`, so this change does not touch that line. `docs/index.md` keeps its card layout but replaces the Rust card's wording and drops the "consumed by many languages" claim.

### D6: Package descriptions match their audiences

`rust/Cargo.toml` keeps a Rust-facing description; `pyproject.toml` describes the Python library rather than "Rust, exposed to Python". Both are one sentence and neither claims other-language support.

### D7: Preserve the executable-example contract

Every Python block that is edited keeps its `#>` markers and is re-run by `tests/test_docs_examples.py`. Blocks that are removed from the README move to the page that now owns them rather than being deleted, so coverage is not silently lost.

## Risks / Trade-offs

- **Removing content from the README loses information** → moved, not deleted: conformance notes go to the conformance page, CLI usage to the CLI page, deeper examples stay in the guides.
- **crates.io packaging could break on the new readme path** → `cargo package --list` is part of verification; the Rust README lives inside `rust/` so the relative path is trivially valid.
- **Numbers can drift again** → the README quotes the canonical table and links to it; the conformance page links rather than copies.
- **Docs example tests fail on edited snippets** → edit blocks by moving them, then run `uv run pytest tests/test_docs_examples.py` before finishing.
- **The two READMEs could contradict each other** → both are checked against the same positioning sentence and the same version facts; the Rust README links to the docs site for behaviour details instead of restating them.

## Migration Plan

Documentation and metadata only. No runtime, API, or packaging behaviour changes; the wheel and crate contents are unchanged except for the rendered README. Rollback is a revert.

## Open Questions

None that affect the specs, approach, or task breakdown.
