# Spec Delta

## Purpose

Defines how the `stixflayer` binary is packaged, versioned, released, and installed across PyPI, crates.io, and direct downloads, so users on Linux and macOS can install it in one command without a Rust toolchain or Python.

## ADDED Requirements

### Requirement: PyPI installation

A `stixflayer-cli` package SHALL be published to PyPI as platform-specific binary wheels built with maturin's `bin` bindings. Installing it SHALL place a `stixflayer` executable on `PATH`. The package MUST NOT install a Python module named `stixflayer`, so it can coexist with the library package.

#### Scenario: pip install provides the command

- **WHEN** a user runs `pip install stixflayer-cli` in a virtual environment
- **THEN** `stixflayer --version` runs from that environment's `bin` directory

#### Scenario: Both packages coexist

- **WHEN** `stixflayer` and `stixflayer-cli` are installed in the same environment
- **THEN** `import stixflayer` resolves to the library and `stixflayer --version` runs the binary

#### Scenario: No Python runtime requirement

- **WHEN** the `stixflayer-cli` wheel is installed into an environment and the binary is executed
- **THEN** it does not require a Python interpreter or the `stixflayer` Python package at runtime

### Requirement: crates.io installation

A `stixflayer-cli` crate SHALL be published to crates.io. `cargo install stixflayer-cli` SHALL produce a `stixflayer` binary without enabling the library's Python bindings or requiring Python development headers.

#### Scenario: Cargo install succeeds without Python

- **WHEN** `cargo install stixflayer-cli` runs on a machine with no Python installation
- **THEN** the build succeeds and installs a `stixflayer` executable

#### Scenario: Installed binary validates a file

- **WHEN** the binary installed by cargo is run against a valid STIX file
- **THEN** it exits 0

### Requirement: GitHub release artifacts

Each CLI release SHALL publish archives for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`, plus a `SHA256SUMS` file and the `install.sh` script, as assets on a `cli-v<version>` release.

#### Scenario: Artifact set is complete

- **WHEN** a `cli-v<version>` release is published
- **THEN** it contains four archives, `SHA256SUMS`, and `install.sh`

#### Scenario: Archive naming is predictable

- **WHEN** a user inspects the release assets
- **THEN** each archive is named `stixflayer-<version>-<target>.tar.gz` for one of the four targets

### Requirement: install.sh behaviour

`install.sh` SHALL detect the host operating system and architecture, download the matching archive for the latest release (or `STIXFLAYER_VERSION` when set), verify its checksum against `SHA256SUMS`, and install the binary to `STIXFLAYER_INSTALL_DIR` or `~/.local/bin` by default. It SHALL fail with a clear message on unsupported platforms.

#### Scenario: Linux x86_64 install

- **WHEN** `install.sh` runs on x86_64 Linux
- **THEN** it installs the `x86_64-unknown-linux-musl` binary and prints the install path

#### Scenario: Version pinning

- **WHEN** `STIXFLAYER_VERSION` is set to a published version
- **THEN** that version is downloaded instead of the latest

#### Scenario: Checksum mismatch aborts

- **WHEN** a downloaded archive does not match `SHA256SUMS`
- **THEN** the script exits non-zero without installing the binary

#### Scenario: Unsupported platform

- **WHEN** `install.sh` runs on an operating system other than Linux or macOS
- **THEN** it exits non-zero with a message naming the supported platforms

### Requirement: Release gating

A `cli-v<version>` release SHALL be published only when the CLI crate's manifest version differs from the most recent `cli-v*` tag, using the same gate mechanism as the existing Python and Rust release channels.

#### Scenario: Unchanged version is skipped

- **WHEN** the CLI crate version matches the latest `cli-v*` tag
- **THEN** no CLI release is published

#### Scenario: Version bump publishes

- **WHEN** the CLI crate version is bumped
- **THEN** the release pipeline builds the four archives, publishes the PyPI and crates.io packages, and creates the `cli-v<version>` tag

### Requirement: Platform scope

The CLI SHALL support Linux and macOS only. Windows builds MUST NOT be published, and the installation paths SHALL report Windows as unsupported rather than producing a broken install.

#### Scenario: Windows is explicitly unsupported

- **WHEN** a Windows user attempts the documented install paths
- **THEN** they receive a clear unsupported-platform message rather than a partial installation
