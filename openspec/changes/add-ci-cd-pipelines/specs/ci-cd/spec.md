# Spec Delta

## Purpose

Define the repository's automated pipelines: a parallel format/lint/compile quality gate and cross-platform test matrix that every change must pass, and a version-bump-gated release process that publishes the Python package to PyPI and the Rust library to crates.io only on merge to main.

## ADDED Requirements

### Requirement: Every change passes a parallel quality gate

The CI pipeline SHALL run on every pull request and every push to main a quality gate composed of format, lint, and compile checks as independent parallel jobs, and the pipeline SHALL fail if any gate job fails.

#### Scenario: Gate jobs run in parallel on a pull request

- **WHEN** a pull request is opened or updated
- **THEN** the format, lint, and compile jobs run concurrently and each reports pass or fail independently

#### Scenario: Gate failure blocks the test stage

- **WHEN** any format, lint, or compile job fails
- **THEN** the test stage does not start and the pipeline run fails

### Requirement: Rust code passes format, lint, and compile checks

The quality gate SHALL verify the Rust workspace is correctly formatted, contains no lint violations (warnings treated as errors), and compiles successfully.

#### Scenario: Unformatted Rust code fails the gate

- **WHEN** Rust source does not match the project's formatting configuration
- **THEN** the Rust format check fails

#### Scenario: Rust lint violation fails the gate

- **WHEN** the Rust linter reports a violation
- **THEN** the Rust lint job fails

#### Scenario: Rust compilation failure fails the gate

- **WHEN** the Rust workspace does not compile
- **THEN** the Rust compile job fails

### Requirement: Python code passes format, lint, and type checks

The quality gate SHALL verify the Python code is correctly formatted, contains no lint violations, and passes the project's type checker; no separate Python compile job is required.

#### Scenario: Python formatting violation fails the gate

- **WHEN** Python source does not match the project's formatting configuration
- **THEN** the Python format check fails

#### Scenario: Python lint violation fails the gate

- **WHEN** the Python linter reports a violation
- **THEN** the Python lint job fails

#### Scenario: Python type error fails the gate

- **WHEN** the Python type checker reports an error
- **THEN** the Python type check job fails

### Requirement: Tests run cross-platform after the gate passes

After all quality-gate jobs pass, the pipeline SHALL run the test stage: the Rust test suite on Linux, macOS, and Windows; and the Python test suite against the compiled extension on Linux, macOS, and Windows.

#### Scenario: Rust tests run on all three operating systems

- **WHEN** the quality gate passes
- **THEN** the Rust test suite runs and passes on Linux, macOS, and Windows runners

#### Scenario: Python tests run against the built extension on all three operating systems

- **WHEN** the quality gate passes
- **THEN** the extension is built from the Python package manifest and the Python test suite runs and passes on Linux, macOS, and Windows runners

#### Scenario: Cross-compile targets are verified for the Rust library

- **WHEN** the test stage runs for Rust
- **THEN** the library compiles for the additional supported targets `aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-musl`

### Requirement: Release runs only on merge to main with a version bump

On a push to main, the release pipeline SHALL publish a package if and only if that package's manifest version advanced beyond the version recorded in the latest matching release tag (`py-v*` for the Python package's manifest, `rust-v*` for the Rust package's manifest). Merges without a version bump SHALL publish nothing.

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

### Requirement: Python release ships one abi3 wheel per supported platform

The Python release SHALL build a single abi3 wheel (compatible with every Python version the package supports) for each supported platform: manylinux x86_64, manylinux aarch64, musllinux x86_64, musllinux aarch64, macOS arm64, and Windows x86_64. Every wheel SHALL be smoke-checked by importing the package before upload, and all wheels SHALL be uploaded together to PyPI in one release.

#### Scenario: Wheels are built for every supported platform

- **WHEN** the Python release pipeline runs
- **THEN** a wheel is produced for each of the six supported platform targets

#### Scenario: Each wheel is smoke-checked before upload

- **WHEN** a wheel has been built
- **THEN** installing it and importing `stixflayer` succeeds on that platform

#### Scenario: All wheels are published as one release

- **WHEN** all wheels pass their smoke checks
- **THEN** every wheel for the bumped version is uploaded to PyPI under a single release

### Requirement: Rust release publishes the workspace crates in dependency order

The Rust release SHALL publish the library to crates.io only after the cross-platform verification passes, and SHALL publish the `stixflayer_derive` crate first whenever its version also advanced, because the main crate's registry entry depends on it.

#### Scenario: Main crate published after its dependency

- **WHEN** the Rust release runs with both crates' versions advanced
- **THEN** `stixflayer_derive` is published to crates.io before the main `stixflayer` crate

#### Scenario: Release only after verification

- **WHEN** any cross-platform verification job fails during the Rust release
- **THEN** nothing is published to crates.io

### Requirement: Successful releases are recorded with version tags

After a package publishes successfully, the release pipeline SHALL create the corresponding version tag (`py-v<version>` or `rust-v<version>`) at the release commit, so subsequent bump comparisons have an authoritative baseline.

#### Scenario: Python publish creates its tag

- **WHEN** the Python package publishes successfully
- **THEN** a tag `py-v<version>` exists at the release commit

#### Scenario: Rust publish creates its tag

- **WHEN** the Rust package publishes successfully
- **THEN** a tag `rust-v<version>` exists at the release commit

### Requirement: Superseded pipeline runs are cancelled

When a new pipeline run starts for a branch or pull request that already has a run in progress, the older run SHALL be cancelled.

#### Scenario: New push cancels the previous run

- **WHEN** a second push to the same branch occurs while a pipeline run is still in progress
- **THEN** the earlier run is cancelled and only the newer run continues
