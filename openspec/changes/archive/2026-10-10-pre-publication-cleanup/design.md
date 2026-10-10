# Design

## Context

The repo is a two-language project: a Rust core (`rust/`) with a pyo3 binding shipped as the Python package `stixflayer` (`src/stixflayer/`), unreleased at v0.1.0. Current state that shapes this design:

- Ruff enforces a single rule (`PLC0415`); running `--select ALL` surfaces 441 violations, concentrated in `tests/` and `benchmarks/` (asserts, missing annotations, docstrings, import order).
- pyrefly is configured (`pyrefly.toml`) and reports 22 errors; its excludes mention directories that no longer exist (`old-python/`, `poc/`).
- The Rust toolchain is Alpine-packaged (no rustup) and **lacks both `cargo fmt` and `cargo clippy`**.
- Dead/scratch code exists: `test_stix()` (returns the literal `"STIX 2.1"`) is registered in the public Python API and stub; `version()` hardcodes `"0.1.0"`; the `heck` dependency is never imported; `test-log` sits in `[dependencies]` but is only used under `#[cfg(test)]`; `opencode.json.bak`, `rust/rust/`, and `.benchmarks/` are stray artifacts.
- The README already contains benchmark tables and a credits line, but the Quick Start targets a nonexistent `python/` directory, the Structure section lists a `poc/` directory, and credits to OASIS cti-rust-stix are minimal.

See proposal.md for motivation.

## Goals / Non-Goals

**Goals:**

- Zero dead or scratch code in both languages, verified by tooling rather than eyeballing.
- Python gates that stay green: an aggressive ruff rule set and a passing `pyrefly check`.
- Rust gates that stay green: `cargo fmt --check` and `clippy -D warnings`.
- A README that leads with the benchmark evidence, positions the one-engine/many-languages architecture, ships verified usage examples, and prominently credits OASIS cti-rust-stix.

**Non-Goals:**

- CI wiring or pre-commit hooks installation (gates are run manually for now; a follow-up change can automate them).
- Publishing mechanics: versioning strategy, release pipelines, crate/PyPI metadata beyond what lint cleanup touches.
- Regenerating benchmark numbers or restructuring the benchmark harness.
- The TypeScript binding itself — only the positioning statement in the README.
- Stubs for every internal module (explicitly out of scope by policy).

## Decisions

### D1: Curated aggressive ruff set, not `select = ["ALL"]`

Select rule families: `E, W, F, I, N, UP, B, C4, SIM, RUF, PL, ANN, D, PTH, PERF, RET, FLY`, with line length 120 (already set). Tests and benchmarks get `per-file-ignores` for the rules that fight test style: `ANN`, `D`, `PLR2004`, `INP001`, `RUF043`, `PT006`.

- **Why**: `ALL` pulls in opinionated families that generate noise without value here (e.g. `CPY001` copyright notices, bandit-style rules on a parsing library), producing noisy diffs across 400+ violations, most in tests. A curated set gets near-ALL strictness for `src/` while keeping tests pragmatic. The measurable target is the same: 0 errors.
- **Alternative rejected**: `select = ["ALL"]` plus a long global ignore list — higher maintenance, and the ignore list would grow every time a new opinionated family appears.
- **Alternative rejected**: adding `__init__.py` to `tests/`/`benchmarks/` to fix `INP001` properly — changes packaging behavior for a lint nit; per-file-ignores is the honest fix.

### D2: pyrefly is the single type-checking gate

Fix all 22 current errors and require `pyrefly check` to pass. Clean `pyrefly.toml` (drop stale excludes).

- **Why**: pyrefly is already a dev dependency and configured; introducing mypy/pyright in parallel would create two sources of truth.
- **Alternative rejected**: running mypy alongside — duplicate gate, no added value before first release.

### D3: Stub policy — entry points only

Keep and complete the two existing stubs (`stixflayer/__init__.pyi`, `stixflayer/stixflayer.pyi`) as the typed public surface; new public surface ships with stub updates; no per-internal stubs. Document the policy in the README's development section.

- **Why**: the compiled extension's module surface *is* the public API; the module-level stub already types all exported classes/functions. Per-internal stubs would be high effort for no user-visible benefit (per the project owner's explicit constraint).
- **Alternative rejected**: `.pyi` for every module — explicitly ruled out as too much work for the benefit.

### D4: Dead-code removal is tool-verified, list-driven

Known removals (verified during planning): `test_stix()` in `functions.rs` + its re-export/registration in `mod.rs` + its stub declaration (no tests reference it); `version()` switches to `env!("CARGO_PKG_VERSION")`; `heck` dropped; `test-log` moved to `[dev-dependencies]`; scratch files deleted. Beyond the known list, clippy's `dead_code`/`unused` warnings and ruff's `F401`/`F841` drive removal — every tool-reported item is confirmed unused (grep + build) before deletion, never deleted on a warning alone.

- **Why**: for a lib crate, `pub` items are invisible to dead-code analysis; the goal is "no dead code we can prove is dead," with the tool list as the safety net.
- **Alternative rejected**: cargo-machete/udeps runs — useful, but manual confirmation with the compiler is sufficient at this codebase size; can be added to CI later.

### D5: Rust gates — install components, then enforce

Install `rustfmt` and `clippy` (Alpine: `apk add rustfmt clippy`; document the requirement for other environments). Run `cargo fmt --all` once; run `clippy --workspace --all-targets -- -D warnings` and fix findings. `#[allow]` is permitted only with a comment explaining why.

- **Why**: the gates cannot run at all until the components exist; enforcing with `-D warnings` from day one prevents regression drift before publication.
- **Alternative rejected**: switching the toolchain to rustup for component management — bigger environment change than this cleanup needs.

### D6: README structure and example verification

Final order: tagline → **Performance (benchmark tables first)** → Why (one Rust engine vs per-language reimplementations) → Languages roadmap (Python + Rust now, TypeScript next) → Quick start (repo root install) → Examples (5 verified snippets: parse + validate a bundle, build an SDO with a builder, handle `ValidationError`, validate a pattern, serialize back to JSON) → "Full docs coming soon" callout → Structure (correct paths) → Credits: a prominent paragraph crediting [OASIS cti-rust-stix](https://github.com/oasis-open/cti-rust-stix) as the foundation the engine is built on. Every example is executed against a freshly built extension (`maturin develop`) before being committed.

- **Why**: the benchmark numbers are the project's strongest differentiator and the owner wants them first; unverified README examples are the most common source of "docs that lie," so the smoke-test step is mandatory.
- **Alternative rejected**: keeping the existing single example — the owner asked for a handful, and each exercises a distinct API surface.

## Risks / Trade-offs

- [Clippy over ~50 Rust files may surface a large warning backlog] → budget the run; use `cargo clippy --fix` for mechanical fixes; `#[allow]` with a comment only where a fix would change behavior; keep `-D warnings` green at the end.
- [Aggressive ruff rules create a large diff in tests/benchmarks] → per-file-ignores (D1) keep the tests' style pragmatic; run the full pytest suite after lint fixes to catch behavioral regressions.
- [Moving `test-log` to `[dev-dependencies]` could break `#[cfg(test)]` unit tests inside `src/`] → dev-dependencies apply to unit tests in the same crate; verified by `cargo test`.
- [README examples drift from the real API] → every snippet is executed as part of the task, not just written.
- [Ruff's `D` (pydocstyle) family on `src/` demands docstrings on the two small glue files] → `src/` is tiny (init + stubs), so this is cheap and improves the published surface; tests/benchmarks are exempt.

## Migration Plan

Single-repo change, no deployment. Implementation order: dead code and dependencies → Rust fmt/clippy → ruff → pyrefly → README last (so numbers and paths reflect the final state). Rollback is a plain `git revert` of the change's commits.

## Open Questions

None — all decisions above were either observed from the codebase or are policy choices recorded in the proposal's assumptions.
