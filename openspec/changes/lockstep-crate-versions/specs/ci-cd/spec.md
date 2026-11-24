# Spec Delta

## MODIFIED Requirements

### Requirement: Release runs only on merge to main with a version bump

On a push to main, the release pipeline SHALL publish a package if and only if that package's effective version advanced beyond the version recorded in the latest matching release tag (`py-v*` for the Python package, `rust-v*` for the Rust package, `cli-v*` for the CLI package). Merges without a version bump SHALL publish nothing.

#### Scenario: Bumped Python version triggers the Python release

- **WHEN** a commit on main raises the `pyproject.toml` version above the latest `py-v*` tag
- **THEN** the Python release pipeline runs

#### Scenario: Bumped Rust version triggers the Rust release

- **WHEN** a commit on main raises the Rust package version above the latest `rust-v*` tag
- **THEN** the Rust release pipeline runs

#### Scenario: Merge without a bump publishes nothing

- **WHEN** a commit is merged to main with unchanged versions in both manifests
- **THEN** no publishing job runs for either package

#### Scenario: Bump of one package does not release the other

- **WHEN** a commit on main raises only the Rust package version
- **THEN** the Rust release runs and the Python release does not

#### Scenario: Workspace-inherited version is compared correctly

- **WHEN** the Rust package inherits its version from a shared workspace value instead of declaring one directly
- **THEN** the gate compares the resolved version against the latest `rust-v*` tag, and the run fails with a version-parsing error rather than silently comparing a non-version value

### Requirement: Rust release publishes the workspace crates in dependency order

The Rust release SHALL publish `stixflayer_derive` to crates.io at the same version as the `stixflayer` library before publishing the library, on every release, because the library's registry entry depends on that exact version. A release run that finds the derive already published at the release version SHALL treat it as the derive published by an earlier attempt of the same release and continue.

#### Scenario: Main crate published after its dependency

- **WHEN** the Rust release runs for version `X.Y.Z`
- **THEN** `stixflayer_derive` `X.Y.Z` is published to crates.io before the main `stixflayer` `X.Y.Z` crate

#### Scenario: Release only after verification

- **WHEN** any cross-platform verification job fails during the Rust release
- **THEN** nothing is published to crates.io

#### Scenario: Retry of a partial release reuses the published derive

- **WHEN** an earlier attempt of the same release already published `stixflayer_derive` at the release version and the run is retried
- **THEN** the release continues with that published derive instead of failing on its presence

#### Scenario: Stale derive cannot be reused by a new release

- **WHEN** the release version advances beyond the version already on crates.io
- **THEN** the derive is published at the new version, so a previously published derive from an earlier release is never the one the library is verified against

## ADDED Requirements

### Requirement: Library and derive share one workspace version

The `stixflayer` library and `stixflayer_derive` SHALL take their version from a single workspace value, and the library SHALL require the derive at exactly that version, so that a library built against a different derive version cannot be resolved. The `stixflayer-cli` crate SHALL keep an independent version because it releases on its own channel.

#### Scenario: Both crates resolve to the workspace version

- **WHEN** the workspace version is `X.Y.Z` and the two crates are packaged
- **THEN** the library and the derive each report `X.Y.Z` as their version

#### Scenario: A mismatched derive fails resolution

- **WHEN** the derive's version and the library's requirement on it disagree
- **THEN** dependency resolution fails with an error naming the mismatched requirement, instead of selecting another compatible version

#### Scenario: CLI version is independent

- **WHEN** the library's version advances
- **THEN** the CLI crate's own version is unchanged and its release channel is gated by `cli-v*` tags alone
