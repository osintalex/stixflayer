# Tasks

## 1. Rust dead code & dependencies

- [x] 1.1 Remove `test_stix()` from `rust/src/python_bindings/functions.rs`, its re-export and `add_function` registration in `rust/src/python_bindings/mod.rs`, and its declaration in `src/stixflayer/stixflayer.pyi`; verify with `grep -rn test_stix rust/src src/` returning nothing and `cargo build` succeeding
- [x] 1.2 Change `version()` in `functions.rs` to return `env!("CARGO_PKG_VERSION")`; verify by rebuilding the extension (`uv run maturin develop`) and running `python -c "import stixflayer; assert stixflayer.version() == '0.1.0'"`
- [x] 1.3 Remove the unused `heck` dependency from `rust/Cargo.toml`; verify with `grep -r "use heck" rust/src` returning nothing and `cargo test` passing
- [x] 1.4 Move `test-log` from `[dependencies]` to `[dev-dependencies]` in `rust/Cargo.toml`; verify with `cargo test` (unit tests under `#[cfg(test)]` still compile and pass)
- [x] 1.5 Delete scratch artifacts: `opencode.json.bak`, the empty `rust/rust/` directory, and the empty `.benchmarks/` directory (add `.benchmarks/` to `.gitignore` only if tooling regenerates it); verify `git status` shows no scratch files and `git ls-files` contains no `*.so`

## 2. Rust format & clippy

- [x] 2.1 Install the missing toolchain components (`apk add rustfmt clippy` on this Alpine environment) and note the requirement for other dev environments; verify `cargo fmt --version` and `cargo clippy --version` both run
- [x] 2.2 Run `cargo fmt --all`; verify `cargo fmt --check` exits clean and `cargo test` still passes
- [x] 2.3 Fix all clippy findings across the workspace (use `cargo clippy --fix` for mechanical ones; `#[allow]` only with an explanatory comment); verify `cargo clippy --workspace --all-targets -- -D warnings` exits clean and `cargo test` passes

## 3. Python lint (ruff)

- [x] 3.1 Replace the ruff config in `pyproject.toml` with the curated aggressive rule set from design D1 (`E, W, F, I, N, UP, B, C4, SIM, RUF, PL, ANN, D, PTH, PERF, RET, FLY`) plus `per-file-ignores` for `tests/**` and `benchmarks/**` (`ANN`, `D`, `PLR2004`, `INP001`, `RUF043`, `PT006`)
- [x] 3.2 Run `uv run ruff check --fix .` and fix the remaining violations manually; verify `uv run ruff check .` reports 0 errors
- [x] 3.3 Run the full Python test suite after lint fixes; verify `uv run pytest` passes

## 4. Python type checking (pyrefly) & stubs

- [x] 4.1 Clean `pyrefly.toml`: remove the stale `old-python/` and `poc/` excludes; verify `uv run pyrefly check` runs with the same scope
- [x] 4.2 Fix all 22 existing pyrefly errors across `src/` and `tests/`; verify `uv run pyrefly check` reports 0 errors
- [x] 4.3 Confirm the stubs match the trimmed API — `src/stixflayer/stixflayer.pyi` declares no `test_stix` and the re-export stubs (`__init__.pyi`) resolve every public name (already covered by 4.2's clean run); verify by type-checking a snippet that imports `Bundle`, `AttackPattern`, and `ValidationError`
- [x] 4.4 Document the stub policy (entry-point stubs only, new public surface ships with stub updates) in the README's development section; verify the policy text is present and consistent with `pyrefly.toml`

## 5. README rewrite

- [x] 5.1 Restructure the README so the Performance section (existing parse/serialize benchmark tables) appears immediately after the tagline; verify by reading the rendered order
- [x] 5.2 Update the Why/Languages sections to state the architecture: one Rust engine shipped into multiple languages — Python + Rust first, TypeScript next — solving per-language STIX implementation drift; verify the roadmap table lists Python + Rust as shipping first and TypeScript as next
- [x] 5.3 Fix stale paths: Quick Start installs from the repo root (not `cd python`) and the Structure section reflects the real tree (no `poc/`); verify each documented command works in a clean checkout
- [x] 5.4 Add an Examples section with five verified Python snippets (parse + validate a bundle, build an SDO with a builder, handle `ValidationError`, validate a pattern, serialize back to JSON) plus a "full docs coming soon" callout; verify every snippet executes against a freshly built extension (`uv run maturin develop`) before committing
- [x] 5.5 Replace the one-line credits with a prominent section crediting [OASIS cti-rust-stix](https://github.com/oasis-open/cti-rust-stix) as the foundation of the engine; verify the credit appears above the license line

## 6. Final integration sweep

- [x] 6.1 Run the complete gate suite in one pass — `uv run ruff check .`, `uv run pyrefly check`, `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test`, `uv run pytest` — and verify all six are green
- [x] 6.2 Verify repo cleanliness: no dead/scratch files remain (`git status` and `git ls-files`), `src/stixflayer/*.so` are untracked, and the change's spec scenarios hold (no `stixflayer.test_stix` attribute on the rebuilt extension)

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- Verify the archived result.
