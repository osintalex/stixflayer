# Proposal

## Why

The first Python (PyPI) and Rust (crates.io) packages are about to be published, but the repo still carries scratch and dead code, the README undersells the benchmark results and describes directories that don't exist, and Python code quality is enforced by a single lint rule. Cleaning this up now avoids publishing junk in v0.1.0 and sets the quality bar the TypeScript binding will inherit next.

## What Changes

- **Dead / scratch code removal (both languages)**
  - Remove the leftover `test_stix()` debug function from the Python extension (`rust/src/python_bindings/functions.rs`), its re-export and registration in `python_bindings/mod.rs`, and the `stixflayer.pyi` stub; make `version()` read `CARGO_PKG_VERSION` instead of a hardcoded string.
  - Remove the unused `heck` dependency from `rust/Cargo.toml`; move `test-log` to `[dev-dependencies]` (it is only used in `#[cfg(test)]` code).
  - Run dead-code analysis for Rust (clippy dead_code / unused warnings, dependency audit) and for Python (ruff unused-import / unused-variable rules), removing everything confirmed unused.
  - Delete scratch artifacts: `opencode.json.bak`, the empty `rust/rust/` directory, and the empty `.benchmarks/` directory; ensure `src/stixflayer/*.so` build outputs stay gitignored and untracked.
- **README rewrite**
  - Lead with the existing speed benchmarks (parse/serialize tables) at the top of the page.
  - State the architecture up front: a single Rust engine shipped into multiple languages — Python + Rust first, TypeScript next — solving the "reimplemented-per-language" pain of STIX development.
  - Note that full docs are coming soon, and include a handful of working Python examples (install, parse + validate, build an object, error handling, pattern validation) that match the real API.
  - Correct the Quick Start path (`cd python` → repo root) and the Structure section (no `poc/` directory exists).
  - Prominently credit [OASIS cti-rust-stix](https://github.com/oasis-open/cti-rust-stix) as the foundation this project is built on.
- **Python lint & type-check strategy**
  - Replace the single-rule ruff config with an aggressive curated rule set (pycodestyle, pyflakes, isort, naming, pyupgrade, bugbear, comprehensions, simplify, perflint, pydocstyle, annotations, ruff-specific) with documented per-file relaxations for tests/benchmarks; fix all resulting violations.
  - Make pyrefly the type-checking gate and fix the 22 existing errors; drop stale excludes from `pyrefly.toml`.
  - Stub strategy: full `.pyi` coverage for the public entry points (already present: `stixflayer/__init__.pyi`, `stixflayer/stixflayer.pyi`), extended as the public surface grows — no stubs for every internal; document this policy.
- **Rust lint & format**
  - Install and run `cargo fmt` and `cargo clippy` (the current toolchain lacks both components); apply formatting and fix or justify every clippy warning.

## Capabilities

### New Capabilities

- `python-api`: The public Python API surface — only intentional, supported entry points are exported (no debug/scratch functions), and entry points are typed via `.pyi` stubs so IDEs and type checkers resolve the API without stubs for every internal.

### Modified Capabilities

(none — no specs exist yet)

## Impact

- **Code**: `rust/src/python_bindings/functions.rs`, `rust/src/python_bindings/mod.rs`, `src/stixflayer/stixflayer.pyi`, `rust/Cargo.toml`, `pyproject.toml`, `pyrefly.toml`, `README.md`, plus lint fixes across `tests/` and `benchmarks/`.
- **Public API**: `stixflayer.test_stix()` disappears (debug-only, unreleased — no compatibility concern).
- **Dependencies**: `heck` removed; `test-log` moved to dev-dependencies.
- **Tooling**: ruff (aggressive set) and pyrefly become enforced Python gates; clippy + rustfmt for Rust (components must be installed in dev environments).
- **Assumptions**: benchmark numbers stay as-is (regeneration out of scope); lint gates are run manually/pre-commit for now — CI wiring is out of scope; the publishing workflow itself (versioning, release pipeline) is out of scope.
