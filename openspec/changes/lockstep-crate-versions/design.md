# Design

## Context

See `proposal.md` — Why. The relevant current state:

- `rust/Cargo.toml` is both the workspace root and the `stixflayer` package (`[workspace] members = [".", "stixflayer_derive", "stixflayer-cli"]`).
- The library requires `stixflayer_derive = { path = "stixflayer_derive", version = "0.1.0" }`; the derive declares its own `version = "0.1.0"`.
- `#![deny(missing_docs)]` in `rust/src/lib.rs` means the derive's emitted code must satisfy a lint that lives in the consuming crate. This is the coupling that semver cannot express.
- `.github/scripts/check_release_gate.py` reads `[package].version` directly with `tomllib`; `.github/workflows/release.yml`'s publish job already reads versions with `cargo metadata`.
- `pyproject.toml` declares `version = "0.1.1"` and `[tool.maturin] manifest-path = "rust/Cargo.toml"`, so the Python build consumes the same manifest being restructured.
- `stixflayer-cli` 0.1.0 is unpublished and requires `stixflayer` 0.1.1, so it is blocked behind this release.

## Goals / Non-Goals

**Goals:**

- One place to change the library's version, with the derive unable to diverge from it.
- Make "the registry has a stale derive at the same version" unrepresentable, rather than detectable.
- Keep the release gate and publish job reading the same version source.
- Leave the CLI's release cadence untouched.

**Non-Goals:**

- No change to the derive's emitted code or to `stixflayer`'s public API.
- No new release tooling (`release-plz`, `cargo-release`).
- No restructure into a virtual workspace root.

## Decisions

### D1: Workspace version inherited by the library and the derive; CLI opts out

`[workspace.package] version` holds the number; `stixflayer` and `stixflayer_derive` set `version.workspace = true`. `stixflayer-cli` keeps a literal version because `cli-v*` is an independent channel.

*Alternatives.* (a) Keep three literals and add a CI equality check — rejected: the check would not have caught the actual failure (derive version matched, *content* differed), and it leaves two sources of truth. (b) Virtual workspace root with packages under `rust/<name>/` — rejected: it moves the manifest path that the gate, maturin, and the release workflow all reference, for no benefit to this problem.

### D2: The derive is required exactly (`=X.Y.Z`)

The derive's public interface is the source text it emits, and that text is validated against host internals: the `StixProperties` trait shape, `deny(missing_docs)`, and `unexpected_cfgs`. A caret range encodes API compatibility, which is not the contract here. At 0.x, caret also spans the entire minor line (`~0.1.1` is identical to `^0.1.1`), so there is no narrower range short of exact.

The practical difference is silence: with a caret requirement, forgetting to update the requirement after a version bump still resolves and still publishes, silently verifying against an older companion. With `=`, it is a resolution error before the build starts.

*Alternatives.* (a) Caret plus a compile-time version assertion emitted by the derive — rejected: catches version skew but not the same-version-different-content failure, at the cost of extra proc-macro logic. (b) Have the derive emit `::stixflayer::properties::...` so it becomes a public, independently versioned crate — deferred; it is the correct end state for independent versioning, but it commits the project to an emitted-code compatibility contract it does not test today (see proposal's out-of-scope list).

*Precedent.* `pyo3` requires `pyo3-macros = "=0.22.6"` and `thiserror` requires `thiserror-impl = "=2.0.20"`; both are private companions. `serde` uses `serde_derive = "1"` because that derive is public and emits only `::serde::` paths.

*Cost accepted.* The derive is republished at every library release even when unchanged — which lockstep already requires. Proc-macro crates may be duplicated in a dependency graph, and no third party can use this derive, so the usual objections to exact pins do not apply.

### D3: The release publishes the derive every time; an existing version means "retry", not "error"

The publish step becomes: if `stixflayer_derive <workspace version>` is absent from crates.io, publish it and wait for indexing; if present, continue. Because the derive version is inherited, a release always introduces a version that has never been published, so a *stale* derive from an earlier release cannot occupy the slot. Presence can therefore only mean an earlier attempt of this same release already published it.

This is a deliberate revision of the "fail if the version already exists" idea: failing would block legitimate retries of a partially completed release (derive published, library publish failed), with no compensating benefit — the staleness it was meant to catch is already impossible under D1/D2.

*Alternatives.* (a) Fail on presence — rejected as above. (b) Compare the published derive's checksum to a freshly packaged one and fail on mismatch — deferred: cargo tarball bytes are not guaranteed stable across versions, and lockstep already removes the failure mode this would detect.

### D4: The gate resolves versions with `cargo metadata`

`read_manifest_version` switches to `cargo metadata --format-version 1 --no-deps` and selects the package by name, which resolves workspace inheritance. Verified failure mode of the current code: given `version.workspace = true`, the script aborts with `cannot parse version: "{'workspace': True}"` and the gate job fails before any release decision.

*Alternatives.* Teach the script to resolve `[workspace.package]` itself — rejected: it duplicates cargo's inheritance rules and would drift from them. The `--version` / `--tags` override flags stay for tests.

*Constraint.* `cargo metadata --no-deps` requires a valid workspace at the checked-out path and does not need the registry, so the gate keeps its current runtime profile.

### D5: 0.1.1 ships inside this change

The library is already at 0.1.1 in both `rust/Cargo.toml` and `pyproject.toml`; only the derive moves (0.1.0 → 0.1.1, by inheritance). No library version bump, no `uv.lock` churn. Sequence on merge: gate sees `rust-v*` below 0.1.1 → verify → publish derive 0.1.1 → publish library 0.1.1 → tag `rust-v0.1.1`; the CLI channel then publishes `stixflayer-cli` 0.1.0.

## Risks / Trade-offs

- **maturin and inherited versions** → `pyproject.toml` builds from `rust/Cargo.toml` with `version.workspace = true`. Verify by building a wheel and confirming the wheel version is 0.1.1. Fallback if maturin cannot resolve it: keep the library's `[package] version` literal and inherit only the derive, accepting a second literal (the gate check still catches drift). *Verified:* maturin builds a wheel whose `METADATA` reports `Version: 0.1.1`, so no fallback is needed.
- **`[workspace.dependencies] stixflayer = { path = "." }`** — a workspace dependency pointing at the root package is unusual → verify with `cargo metadata`; fallback is to leave the CLI's dependency literal in place.
- **Local `cargo package` cannot fully verify before publish** → after the change, `cargo package -p stixflayer` downloads `stixflayer_derive 0.1.1`, which does not exist until the release publishes it. Local verification therefore uses `cargo build`/`cargo test --workspace` plus `cargo package --no-verify` for contents, and the registry-deps build is proven by the publish job itself. This is inherent to a two-crate publish, not a regression. *Verified:* `cargo package -p stixflayer` aborts before building, with or without `--no-verify`, reporting `failed to select a version for the requirement stixflayer_derive = "=0.1.1"` against the crates.io index (only 0.1.0 exists). Package contents were checked with a temporary `--config patch.crates-io.stixflayer_derive.path=...` pointing at the workspace derive; the resulting normalized manifest records the requirement as `=0.1.1` and includes the README.
- **Derive publish failure stalls the release** → the derive is published first by design, so a failure is loud and nothing partial reaches the library slot.
- **crates.io immutability** → if 0.1.1 publishes with a defect, `cargo yank --version 0.1.1` and release 0.1.2; the derive must move with it.
- **Exact pin plus a manual `[patch]`** → patching the derive locally now requires matching the exact version; acceptable because the derive is not usable outside the crate.

## Migration Plan

1. Restructure the three manifests and refresh `rust/Cargo.lock`.
2. Update the gate script and its invocation; keep `--version`/`--tags` behavior for tests.
3. Update the release workflow's derive step and the CLI job's `publish_if_missing` helper.
4. Verify locally: `cargo metadata`, `cargo build --workspace`, `cargo test --workspace`, `cargo package -p stixflayer --no-verify`, wheel build for the inherited version.
5. Merge to main and let the pipeline publish derive 0.1.1 → library 0.1.1 → tag; then confirm the CLI channel publishes 0.1.0.

Rollback: revert the manifests and workflow; a published crate cannot be unpublished, so a bad 0.1.1 is yanked and superseded by 0.1.2.
