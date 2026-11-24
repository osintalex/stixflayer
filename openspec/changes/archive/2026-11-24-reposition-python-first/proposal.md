# Proposal

## Why

The repository presents itself as a polyglot project — "one Rust engine, consumed by many languages", with a roadmap table for TypeScript, Go, Java, and WASM — while every shipped user is a Python user, every guide is a Python guide, and every release artifact is a Python wheel plus a Rust crate. The polyglot framing sets expectations the project does not meet, distracts from the two things it actually is, and appears in seven places across the README, docs site, crate metadata, and Rust API docs.

The documentation also contradicts itself. The README claims a 40× speedup for `poisonivy` while its own numbers (99 ms → 2.3 ms) and `benchmarks/BENCHMARKING.md` say 43×. The spec-conformance notes — the actual evidence for "more correct" — are buried at the bottom of a 232-line README instead of being a navigable page. The README is also the crates.io landing page, so a Python-first rewrite would misrepresent the Rust crate, which remains a marketed product.

## What Changes

- **One positioning statement, used everywhere**: stixflayer is the fastest and most spec-correct STIX 2.1 library for Python, powered by a Rust engine, with a native CLI for validating STIX files at scale. Rust remains a first-class, marketed crate; other language bindings are explicitly deferred until users ask.
- **README rewritten for concision**: 232 lines to roughly 90. Positioning, `pip install`, `curl | sh` CLI install, three short examples, links to the guides, license and credits. The language roadmap table is removed; the Rust crate gets a single accurate paragraph and docs.rs link.
- **Registry-specific READMEs**: `rust/README.md` becomes the crates.io `readme`, so GitHub tells the Python-first story while crates.io and docs.rs tell the Rust story. `pyproject.toml` and `rust/Cargo.toml` descriptions are aligned with their respective audiences.
- **One canonical performance table**: `benchmarks/BENCHMARKING.md` is the single source of truth. README and docs quote a range and link to it; the 40×/43× contradiction is removed.
- **Spec conformance gets its own page**: the existing conformance notes move to `docs/guides/conformance.md`, joined by the real-world evidence (which feeds the validator accepts, and where it diverges from `stix2`), and linked from the README.
- **CLI entry points**: quickstart gains the CLI install and a one-command validation example; the docs index and README link the CLI reference that `add-validation-cli` adds.
- **Docs site metadata**: `mkdocs.yml` `site_description` and `docs/index.md` drop the "consumed by many languages" claim and the unsupported 10–40× range, and link the CLI.
- **Stale claims removed**: no "TypeScript is next", no WASM/Extism roadmap, no "Rust users: cargo add" without context, no performance number that cannot be reproduced from the committed harness.

This change is documentation and metadata only. It does not alter library or CLI behaviour.

## Capabilities

### New Capabilities

- `project-positioning`: the project states one audience and one promise consistently across the GitHub README, the crates.io/docs.rs README, the docs site, and package metadata; every quantitative claim is reproducible from a committed source; user-facing documentation is concise and free of aspirational roadmap claims.

## Impact

- **Documentation**: `README.md`, new `rust/README.md`, `docs/index.md`, `docs/quickstart.md`, `docs/guides/conformance.md`, `docs/guides/validation.md`, `mkdocs.yml`, `benchmarks/BENCHMARKING.md`.
- **Metadata**: `rust/Cargo.toml` (`readme`, description), `pyproject.toml` (description), `mkdocs.yml` (site description).
- **No code**: no Rust, Python, or CLI behaviour changes. The docs-example harness must keep passing, so any edited code block must still execute with its `#>` expectations.
- **Ordering**: the CLI documentation depends on `add-validation-cli` existing; the conformance page quotes the fixes from `fix-validation-correctness`. Both can be written against the planned behaviour, but the examples only run once those changes land.
