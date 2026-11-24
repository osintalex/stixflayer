# Tasks

## 1. Workspace version and shared dependencies

- [x] 1.1 Add `[workspace.package]` (`version = "0.1.1"`, `edition`, `license`, `repository`) to `rust/Cargo.toml` and make the `stixflayer` package inherit those fields; verify `cargo metadata --no-deps` reports `stixflayer` at 0.1.1 and `cargo build -p stixflayer` passes
- [x] 1.2 Make `stixflayer_derive` inherit `version`, `edition`, `license`, and `repository` (keeping its own `description`); verify `cargo metadata --no-deps` reports `stixflayer_derive` at 0.1.1, not 0.1.0
- [x] 1.3 Add `[workspace.dependencies]` with `stixflayer_derive = { path = "stixflayer_derive", version = "=0.1.1" }` and `stixflayer = { path = ".", version = "0.1.1" }`, consumed with `.workspace = true` by the library and the CLI; verify `cargo tree -p stixflayer` shows `stixflayer_derive v0.1.1` and `cargo build --workspace` passes
- [x] 1.4 Verify the exact pin fails loudly: in a scratch copy of the workspace, raise the derive's version without touching the requirement and confirm resolution errors naming the mismatch; confirm the same change under a caret requirement resolves silently, as design D2 claims
- [x] 1.5 Keep `stixflayer-cli`'s version literal at 0.1.0; verify `cargo metadata --no-deps` reports 0.1.0 for `stixflayer-cli` while the library and derive report 0.1.1
- [x] 1.6 Refresh `rust/Cargo.lock` and verify `cargo check --workspace --locked` passes with the lock recording `stixflayer_derive` 0.1.1

## 2. Release gate reads effective versions

- [x] 2.1 Replace the `tomllib` read of `[package].version` with package selection from `cargo metadata --format-version 1 --no-deps`, keeping the `--version` and `--tags` overrides; verify running the script on the repo emits `rust_release=true`, `rust_version=0.1.1`, and still reads `pyproject.toml` for the Python channel
- [x] 2.2 Add `tests/test_release_gate.py` covering the tag comparison through `--version` and the workspace-inherited resolution path, skipped when `cargo` is unavailable; verify `pytest tests/test_release_gate.py` passes and that the Python gate job's `pytest` run collects it
- [x] 2.3 Verify the reported failure mode is gone: run the gate against a fixture manifest using `version.workspace = true` and confirm it reports 0.1.1 instead of aborting with `cannot parse version: "{'workspace': True}"`

## 3. Release workflow publishes the derive in lockstep

- [x] 3.1 Rewrite the `rust-publish` derive steps: remove the "skip when already published" branch, publish at the resolved workspace version, treat an existing version as an earlier attempt of the same release, and wait for crates.io indexing before publishing the library; verify the YAML parses and trace the step order for both the fresh-release and retry cases
- [x] 3.2 Align the CLI job's `publish_if_missing` helper with the same semantics and the derive → library → CLI order; verify the YAML parses and the helper publishes each crate only when absent at its own version
- [x] 3.3 Verify both publishing jobs still share the `crates-io-publish` concurrency group and that `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"` succeeds

## 4. Pre-release verification

- [x] 4.1 Run the local quality gate: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo build --workspace`, `cargo test --workspace` — all pass
- [x] 4.2 Verify package contents with `cargo package -p stixflayer --no-verify --list`: the README is included and the normalized manifest records `stixflayer_derive` at `=0.1.1`
- [x] 4.3 Build a wheel with maturin and confirm its version is 0.1.1 with the inherited manifest version; if maturin cannot resolve `version.workspace = true`, apply the design's fallback (literal library version, inherited derive) and record the outcome in design.md
- [x] 4.4 Confirm and record that `cargo package -p stixflayer` verification cannot pass before `stixflayer_derive` 0.1.1 is published, so the registry-dependencies build is proven by the publish job rather than locally

## 5. Release and post-release verification

- [ ] 5.1 Merge to main and confirm the gate reports `rust_release=true` with `rust_version=0.1.1`
- [ ] 5.2 Confirm `stixflayer_derive` 0.1.1 publishes before `stixflayer` 0.1.1, and verify the crates.io API returns 200 for both versions
- [ ] 5.3 Confirm the `rust-v0.1.1` tag exists at the release commit and that docs.rs builds the 0.1.1 documentation
- [ ] 5.4 Confirm the CLI channel publishes `stixflayer-cli` 0.1.0 with a `cli-v0.1.0` release carrying the four archives, `SHA256SUMS`, and `install.sh`

## Workflow follow-up

- Archive the change with `/opsx-archive` once 5.1–5.4 pass.
- Treat the unused `paste`, `pathbuf`, and `tlsh` dependencies flagged by Cargo's manifest lints as a separate follow-up change.
