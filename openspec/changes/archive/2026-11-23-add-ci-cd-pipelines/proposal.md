# Proposal

## Why

stixflayer is about to publish for the first time (Python package + Rust library, both at 0.1.0), but the repo has no CI at all: nothing verifies that a pull request compiles, lints, and passes tests on every supported platform, and nothing prevents an accidental or forgetful release. Professional cross-platform distribution needs automated quality gates on every change and reproducible, version-bump-gated releases on merge to main.

## What Changes

- **CI quality gate (parallel stage 1)** — a GitHub Actions workflow runs format, lint, and compile checks as parallel jobs that must all pass:
  - Rust: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo build` (workspace).
  - Python: `ruff format --check`, `ruff check`, `pyrefly check`. (No Python compile job — nothing to compile until the extension is built in the test stage.)
- **Test stage (stage 2)** — runs only after stage 1 passes:
  - Rust: `cargo test` on ubuntu, macos, and windows runners, plus build checks for the additional targets `aarch64-unknown-linux-gnu` (native ARM runner) and `x86_64-unknown-linux-musl` (official Alpine image) — a library ships as source on crates.io, so targets are verified by compiling, not by artifacts.
  - Python: build the extension with maturin, then run `pytest` (benchmarks disabled) on each OS and on every supported Python version (3.11–3.13).
- **Release workflow gated on version bumps** — on merge to main, a release runs **if and only if** the package's version was bumped:
  - The gate compares `pyproject.toml` / `rust/Cargo.toml` versions against the latest `py-v*` / `rust-v*` git tags; an unchanged version publishes nothing.
  - **Python release**: maturin builds one abi3 wheel per platform — linux x86_64 + aarch64 (manylinux), linux x86_64 + aarch64 (musllinux), macOS arm64, Windows x86_64 — smoke-checks each artifact, uploads all wheels to PyPI, and creates the `py-v*` tag. Requires switching the extension to abi3 (`abi3-py311` in `rust/Cargo.toml`), so one wheel per platform serves every Python ≥ 3.11.
  - **Rust release**: publishes the `stixflayer_derive` proc-macro crate (if bumped) then the main `stixflayer` crate to crates.io and creates the `rust-v*` tag. Requires renaming the proc-macro crate from the inherited `stix_derive` — that name is already taken on crates.io by the upstream OASIS `cti-rust-stix` project, whose v0.1.0 has an incompatible API.
  - **Registry-compliant crate metadata** — the first release attempt was rejected by crates.io (`400 Bad Request: missing or empty metadata fields: description`): neither workspace manifest carried publish metadata. Both crate manifests gain the metadata crates.io requires and recommends: `description` and `repository` on both crates; the main crate additionally packages the repository README and declares `documentation`. Verified pre-publish via `cargo package` completing without missing-metadata warnings.
- **Workflow hygiene** — concurrency cancellation of superseded runs, a minimal third-party-action policy (GitHub first-party actions plus `maturin-action` and `gh-action-pypi-publish`; no toolchain or cache actions), lightweight container images for the Python gate jobs, pinned action versions, and documented secret prerequisites (PyPI trusted publishing, `CARGO_REGISTRY_TOKEN`).

## Capabilities

### New Capabilities

- `ci-cd`: The repository's automated pipelines — the parallel format/lint/compile quality gate, the cross-platform test matrix for both the Rust library and the Python package, and the version-bump-gated release process that publishes to PyPI and crates.io only on merge to main when the corresponding manifest version advanced.

### Modified Capabilities

(none — `python-api` and `error-reporting` requirements are unaffected; CI builds and publishes the existing API surface)

## Impact

- **New files**: `.github/workflows/ci.yml`, `.github/workflows/release.yml`.
- **Modified**: `rust/Cargo.toml` (add `abi3-py311` to the `pyo3` feature chain; rename the proc-macro crate to `stixflayer_derive` and add the registry version to its path dependency; add registry publish metadata), `rust/stixflayer_derive/Cargo.toml` (add registry publish metadata: `description`, `repository`), `pyproject.toml` (add Python 3.13 classifier), `README.md` (CI badge only — pipeline documentation lives in the OpenSpec change, not the public README).
- **Secrets/external setup**: PyPI trusted publishing configured for the GitHub environment, `CARGO_REGISTRY_TOKEN` repository secret, first tags created by the initial releases.
- **No product code changes**: validation logic, public API, and error reporting are untouched; workflows only build, verify, and publish them.
- **Artifact behavior**: Python wheels change from per-version CPython extensions to a single abi3 wheel per platform — pre-release, so no compatibility concern.
