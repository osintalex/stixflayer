# Proposal

## Why

The `stixflayer` 0.1.1 release failed at `cargo publish` because the `stixflayer_derive` 0.1.0 crate on crates.io predates the `#[doc]` attribute added to its generated `*_VARIANTS` const in commit `c00f095`. The repo still declared `stixflayer_derive` version 0.1.0, so the release job's "publish the derive only if that version is missing from crates.io" check saw 0.1.0 and skipped it. Verification then downloaded the stale published crate, and `#![deny(missing_docs)]` in the library rejected three undocumented generated constants.

Nothing in CI could catch this: `cargo test --workspace` resolves the derive through its path dependency (current source, passes), while only `cargo publish` builds against the registry copy. The version of the derive and the library's requirement on it are hand-maintained in two separate places, so they can drift silently — and a previous change's plan explicitly offered "leave the derive at 0.1.0 if it has no changes", which is the assumption that broke.

## What Changes

- Adopt `[workspace.package] version` as the single version source for `stixflayer` and `stixflayer_derive`; both inherit it with `version.workspace = true`. `stixflayer-cli` keeps its own explicit version because it releases on its own `cli-v*` cadence.
- Declare intra-workspace dependencies once in `[workspace.dependencies]`: `stixflayer_derive` required **exactly** (`=X.Y.Z`) and `stixflayer` required with a caret range for the CLI.
- Change the Rust release so the derive is published at the library's version on every release, instead of "only if missing". Because the derive version is inherited, a release always publishes a derive version that has never existed before, which makes a stale companion unrepresentable. A retry of a partially-completed release reuses the derive already published at that version.
- Make the release gate read the effective package version through `cargo metadata` instead of parsing `[package] version` from the manifest with `tomllib`, which would otherwise receive a `version.workspace = true` table and abort.
- Ship the blocked 0.1.1 release as part of this change: the derive moves to 0.1.1 and the library stays at 0.1.1, so `cargo publish -p stixflayer` verifies against the fixed derive. That in turn unblocks `stixflayer-cli` 0.1.0, which is not on crates.io yet.

**Out of scope** (considered and deliberately not done):

- Turning `stixflayer_derive` into a public, independently versioned derive by emitting `::stixflayer::properties::...` instead of `crate::properties`. That would make caret versioning correct, but it commits the project to a stable emitted-code contract it does not test today.
- Moving to a virtual workspace root (`rust/Cargo.toml` containing only `[workspace]`), which would move the manifest path the gate and maturin depend on.
- Replacing the version-vs-tag gate with `release-plz` or `cargo-release`.
- Removing the genuinely unused `paste`, `pathbuf`, and `tlsh` dependencies that Cargo's manifest lints flag.

## Capabilities

### New Capabilities

None. This change alters release behavior already owned by `ci-cd`.

### Modified Capabilities

- `ci-cd`: the Rust release publishes the derive in lockstep at the library's version rather than conditionally on absence; a new requirement makes the workspace version the single version source for the library and its derive and pins the dependency exactly; the version-bump gate must read inherited versions correctly.

## Impact

- `rust/Cargo.toml` — workspace version, shared metadata, `[workspace.dependencies]`, inherited version, exact derive requirement.
- `rust/stixflayer_derive/Cargo.toml` — inherits version/edition/license/repository; bumps 0.1.0 → 0.1.1.
- `rust/stixflayer-cli/Cargo.toml` — consumes the shared `stixflayer` dependency; keeps version 0.1.0.
- `rust/Cargo.lock` — re-resolves the derive at 0.1.1.
- `.github/workflows/release.yml` — derive publishing step in `rust-publish` and the CLI job's `publish_if_missing` helper.
- `.github/scripts/check_release_gate.py` — resolves workspace-inherited versions via `cargo metadata`.
- No public API change to the `stixflayer` crate and no Python API change. The Python package version in `pyproject.toml` must stay equal to the workspace version because maturin builds from `rust/Cargo.toml`; that coupling is unchanged by this proposal but must be verified for inherited versions.
