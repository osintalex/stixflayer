# Design

## Context

The repo builds two distributables from one codebase: a Python package (`stixflayer`, maturin/pyo3, manifest `pyproject.toml`, Rust sources under `rust/`) and a Rust library crate (`stixflayer` in the `rust/` workspace, which also contains the `stixflayer_derive` proc-macro crate it depends on — renamed from the inherited `stix_derive` during implementation, since that name is already taken on crates.io by the upstream OASIS `cti-rust-stix` project, whose v0.1.0 has an incompatible API). Existing tooling: ruff (format+lint), pyrefly (types), pytest + pytest-benchmark on the Python side; `cargo fmt`, `cargo clippy`, `cargo test` on the Rust side; `uv` manages Python deps (`uv.lock`). There is no `.github/` directory yet, no git tags, and nothing is published. `.cargo/config.toml` already sets `PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1`. See proposal.md for motivation and specs/ci-cd for the behavior contract.

User-confirmed scope decisions: abi3 single-wheel builds; wheel matrix includes manylinux x86_64+aarch64 and musllinux x86_64+aarch64 plus macOS arm64 and Windows x86_64; Rust matrix adds aarch64-linux-gnu and x86_64-musl cross-compile checks; release gate uses git tags.

After the first fully green CI run (14/14 jobs on the initial implementation), the user requested a leaner pipeline: lightweight containers instead of full VMs for the Python gate jobs, a minimal third-party-action policy (D8), and a Python version matrix for the test stage. Those decisions are folded into the decisions below; the workflow files were reworked accordingly.

## Goals / Non-Goals

**Goals:**
- Two GitHub Actions workflows (`.github/workflows/ci.yml`, `.github/workflows/release.yml`) implementing the parallel gate → test stage → gated release pipeline.
- Publishes that are reproducible, serialized, and idempotent (a re-run after a failed publish does not double-publish).

**Non-Goals:**
- Release automation for future language targets (JS/TS, Go, Java/WASM per ARCHITECTURE.md) — added later as new capabilities.
- Version-bump automation (release-please / bump tooling); versions are bumped by hand in the manifests.
- Branch protection / required status checks configuration (GitHub settings, listed only as a setup prerequisite).
- Nightly scheduled jobs, coverage reporting, or benchmark trend tracking.

## Decisions

**D1 — Two workflow files, each self-contained.**
`ci.yml` runs on pull requests and pushes to main (gate + tests). `release.yml` runs on pushes to main only (verify + publish, gated on version bump). Alternatives: one workflow with conditional jobs — rejected because releases need different permissions (`id-token`, `contents: write`) and a different concurrency policy; triggering release via `workflow_run` after ci.yml — rejected as fragile (hidden failure modes when the triggering run is skipped) and harder to reason about; release.yml re-running verification itself costs some compute but keeps the publish path independently auditable.

**D2 — Job topology of ci.yml.**
Stage 1 (all parallel, `fail-fast` behavior via job independence): `rust-fmt` (`cargo fmt --all -- --check`), `rust-clippy` (`cargo clippy --workspace --all-targets -- -D warnings`), `rust-build` (`cargo build --workspace`), `py-format` (`ruff format --check`), `py-lint` (`ruff check`), `py-typecheck` (`pyrefly check`). No Python compile job (nothing to compile before the extension exists). Rust jobs run on the toolchain preinstalled on every runner image (ubuntu, macos, and windows images all ship Rust, rustup, rustfmt, and cargo; the clippy job adds its component with `rustup component add clippy`) — no toolchain-installation action. A container job on an official `rust` image would not help: those images install rustup's `--profile minimal` (no clippy, no rustfmt), so they need the same component add plus an image pull; the runner toolchain is strictly faster. Python gate jobs run as container jobs on `ghcr.io/astral-sh/uv:python3.13-bookworm-slim` (uv and the latest supported Python preinstalled), which starts faster and exposes a far smaller attack surface than a full Ubuntu VM; the image is glibc-based (Debian bookworm), so the runner-mounted Node runtime keeps `actions/checkout` working inside the container. Stage 2 (`needs:` all six): `rust-test` matrix over ubuntu/macos/windows (`cargo test --workspace`), plus two target-verification jobs replacing the earlier `cross`-based matrix — `aarch64-unknown-linux-gnu` verified by a plain `cargo build --workspace` on a native `ubuntu-24.04-arm` runner (free for public repositories; native build, no emulator), and `x86_64-unknown-linux-musl` cross-compiled with `rustup target add` + `cargo build --target` — rustc's bundled lld (self-contained linking) handles musl, and the crate is pure Rust with `extension-module` (never links libpython), so no musl toolchain, container, or Docker is needed. `py-test` is a matrix over ubuntu/macos/windows × Python {3.11, 3.12, 3.13}: uv — installed via the official installer script, no dedicated action — creates each interpreter's environment (`uv sync --python <version>`, downloading interpreters the runner lacks), the maturin build backend compiles the extension, then `pytest --benchmark-disable` runs (benchmark tests still execute once, they just don't time). Running the suite on every supported Python version is a user decision that revises the earlier single-version (3.13-only) stance.

**D3 — abi3 switch.**
Change `rust/Cargo.toml` so the `pyo3` feature enables pyo3's abi3: `pyo3 = ["dep:pyo3", "pyo3/abi3-py311"]`. Every build (dev and CI) then produces an abi3-py311 extension, and maturin emits one wheel per platform tagged `abi3` (cp37-abi3-style tag covering ≥3.11). Alternative (per-version wheels, 9 jobs) rejected as slower with no benefit pre-1.0. The existing `PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1` is kept: it is what lets pyo3 0.22 build against runner Pythons newer than its supported list; removing it is revisited with the next pyo3 upgrade. `pyproject.toml` gains a 3.13 classifier; `requires-python` stays `>=3.11`.

**D4 — Version-bump gate via tags.**
On push to main, release.yml fetches all tags, finds the latest `py-v*` and `rust-v*` tags, and compares each against the current version read from `pyproject.toml` and `rust/Cargo.toml`. Comparison is segment-wise numeric (semver-aware), not string sort. No matching tag (first release) counts as advanced. A package whose version equals its latest tag publishes nothing; if neither package advanced, the workflow completes without publishing. Alternative (querying PyPI/crates.io for existing versions) rejected as the primary gate because it couples release decisions to registry availability — but a registry existence check *is* used inside the Rust publish for `stixflayer_derive` (below), where a tag cannot record a second crate's version.

**D5 — Rust release and the stixflayer_derive wrinkle.**
crates.io requires a path dependency to be published first, so the Rust publish job: (1) checks whether `stixflayer_derive`'s current version exists on crates.io (registry API GET → 404 means unpublished); (2) if unpublished, `cargo publish -p stixflayer_derive`; (3) waits for the registry to index it (the main crate's verification build must resolve it); (4) `cargo publish -p stixflayer`; (5) tag `rust-v<version>` and push. Both publishes also skip when the version already exists, so a re-run after a partial failure converges. Convention documented for maintainers: the two crates' versions are bumped together, and the gate keys on the main crate's version — a `stixflayer_derive`-only bump rides along with the next main-crate release. All of this runs only after release.yml's own verification stage (same matrix and cross-target checks as ci.yml's test stage) passes, per the spec. The path dependency in the main crate's manifest carries a registry version requirement (`stixflayer_derive = { path = ..., version = "0.1.0" }`), which crates.io requires for publishing.

**D6 — Python release topology.**
Build stage: `maturin-action` job matrix — linux x86_64 (manylinux), linux aarch64 (manylinux, native `ubuntu-24.04-arm` runner where available, QEMU fallback), linux x86_64 + aarch64 musllinux (`maturin-action`'s musl toolchain images), macOS arm64, Windows x86_64. Each job uploads its wheel as a workflow artifact. Smoke stage: on each runner, install the just-built wheel into a fresh venv created with plain `python -m venv` + pip (keeping uv and its installer out of the release path) and `import stixflayer` plus a trivial API call; musl wheels are checked inside an Alpine container, where the runner's glibc build cannot load them. Publish stage: single `pypa/gh-action-pypi-publish` job using **trusted publishing** (OIDC; no PyPI token secret) with the `pypi` GitHub environment, uploading all collected wheels as one PyPI release; then tag `py-v<version>` and push. Alternatives: `maturin upload` per matrix job — rejected (token management, non-atomic multi-part release); TestPyPI staging — rejected as permanent ceremony for a single-package repo (the smoke check + one-environment publish is the pragmatic gate).

**D7 — Tags and permissions.**
release.yml gets `permissions: contents: write` (tag push) and `id-token: write` (PyPI trusted publishing). Tags are pushed with the workflow's GITHUB_TOKEN. Tag push happens strictly after the successful publish of that package.

**D8 — Hygiene: minimal third-party actions, no caching.**
`concurrency`: ci.yml groups on `github.ref` with `cancel-in-progress: true`; release.yml groups on `github.event`-independent `release` key with `cancel-in-progress: false` so quick successive merges to main serialize releases and each run's gate sees the previous run's new tag. **Action allowlist (user-set policy):** only GitHub first-party actions (`actions/checkout`, `actions/upload-artifact`, `actions/download-artifact`) plus `PyO3/maturin-action` and `pypa/gh-action-pypi-publish` — both long-maintained by their ecosystems and load-bearing (container orchestration, OIDC publishing); everything else is runner-preinstalled tools, official container images, and plain shell. No toolchain actions (dtolnay/rust-toolchain is gone — runner images preinstall the Rust toolchain) and no cache actions (Swatinem/rust-cache and setup-uv's cache are gone — cold cargo builds cost roughly 1–3 minutes per job, an accepted trade-off). uv reaches jobs via the official installer script or preinstallation in the gate container image. All remaining actions stay pinned to full-length commit SHAs (supply-chain hardening; readability cost accepted).

**Docker policy (user-set):** builds always run on the plain runner toolchain. A container is justified only when a foreign OS must be *executed* — e.g., loading musllinux wheels in the smoke stage. Never use Docker to cross-compile: `rustup target add` + rustc's bundled lld covers foreign-target builds for pure-Rust crates.

**D9 — Credential model.**
One credential in the whole pipeline. PyPI uses trusted publishing: release.yml holds `id-token: write` and the publish job runs under the `pypi` GitHub environment; `pypa/gh-action-pypi-publish` exchanges the run's short-lived OIDC token for an upload session, validated against the one-time trusted-publisher registration (owner/repo/workflow name/environment) made on PyPI's website — no PyPI token is stored in the repository. crates.io, which has no OIDC support, uses the `CARGO_REGISTRY_TOKEN` repository secret, read automatically by `cargo publish` from the job env. Fallback if trusted publishing is ever unavailable: store a fine-grained `PYPI_API_TOKEN` as a secret scoped to the `pypi` environment and pass it to the publish action's `password` input — deliberately not implemented now to keep long-lived tokens out by default.

## Risks / Trade-offs

- [Native aarch64 Linux runner unavailable] → the release path keeps maturin-action's QEMU fallback (slower but correct); the CI aarch64 check would need an emulated equivalent. Native `ubuntu-24.04-arm` runners are free for public repositories, so this is not expected to bite.
- [musl + pyo3 linking quirks] → build via maturin-action's musl images and rely on the per-wheel smoke check to catch a broken wheel before publish.
- [Failed publish after `stixflayer_derive` published] → crates.io cannot unpublish; the existence checks make re-runs skip already-published crates and retry only the remaining one, so state converges.
- [First release has no baseline tags] → gate treats "no matching tag" as advanced; 0.1.0 publishes and creates the baseline.
- [fmt/clippy/build jobs compile redundantly and pay cold builds] → accepted deliberately (user wants independent parallel gate jobs and no cache actions); each cargo job spends roughly 1–3 minutes compiling dependencies. Revisit with first-party `actions/cache` or sccache only if that cost measurably hurts.
- [pyo3 0.22 vs newest CPython] → abi3-py311 minimizes version coupling; the forward-compat env var stays; pyo3 upgrade is a separate change.
- [Publishing prerequisites missing at first merge to main] → release fails visibly, nothing publishes, no tag is created; the prerequisites (PyPI trusted publisher for this repo/workflow/environment, `CARGO_REGISTRY_TOKEN` secret) are explicit setup tasks.

## Migration Plan

1. Land workflows + abi3 feature change; configure PyPI trusted publishing and the crates.io secret.
2. Enable required status checks for ci.yml jobs on main (GitHub settings).
3. Merge to main with versions still at 0.1.0 → first release publishes both packages and creates `py-v0.1.0` / `rust-v0.1.0`.
4. Rollback: delete the workflow files; already-published versions can only be yanked (PyPI) or remain (crates.io) — pre-1.0, acceptable.

## Open Questions

None — platform scope, wheel strategy, and gate mechanism were confirmed by the user before planning.
