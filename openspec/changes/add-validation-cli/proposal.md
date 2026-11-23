# Proposal

## Why

Python users can validate STIX with `pip install stixflayer`, but there is no way to validate STIX in CI, in a container, or in a repository scan without installing Python and writing a script. The community's most valuable public artefacts are files: Amnesty's `.stix2` IOC feeds, MVT's indicator collections, MITRE ATT&CK's 53 MB `enterprise-attack.json`, MISP exports. Validating them is currently a Python chore; it should be one binary and one command.

A Rust CLI is also the fastest way to prove the engine's correctness claim in public: run it against real feeds, publish the findings, and give downstream projects a zero-dependency way to gate their own STIX in GitHub Actions.

## What Changes

- **New workspace crate `rust/stixflayer-cli`** producing a binary named `stixflayer`, built with `clap` and `rayon`. The library gains no parallelism: rayon is a CLI-only dependency, and the CLI orchestrates the public engine APIs (`StixObject::from_value_outcome`, `Bundle::check_invariants`).
- **Library default features become `[]`** and `[tool.maturin]` passes `features = ["pyo3"]`, so the CLI and `cargo install stixflayer-cli` never require Python, while the wheel build is unchanged.
- **Inputs**: one or more paths (files or directories, directories walked recursively) plus `-` for stdin. Candidate extensions are `.json`, `.jsonl`, `.stix2`, and `.stix`; explicitly named paths are always validated regardless of extension. `.jsonl` files are read as one JSON document per non-empty line.
- **Skip policy**: valid JSON without a STIX `type` is `skipped: "not_stix"`; a `.json` file that does not parse is `skipped: "not_json"`; a STIX document whose `spec_version` is not `2.1` is `skipped: "unsupported_spec_version"`. Skip reasons are free-form strings, not a frozen enum. An unreadable file is an operational failure (exit 2), not a skip.
- **Object-level parallelism**: read files, then validate objects in parallel with rayon; `-j/--jobs <N>` sets the worker count (default: all logical cores). Output is ordered by path so results are deterministic even though execution order is not.
- **Stable JSON report** via `--json`, with `schema_version: 1` on the envelope and additive-only evolution thereafter. `--print-schema` prints a checked-in JSON Schema for the report. The report reuses the engine's `Entry` shape for errors and warnings and never embeds the parsed document.
- **Exit codes**: `0` all validated documents valid (skips allowed), `1` at least one invalid document, `2` usage or I/O failure.
- **Validation options**: `--allow-custom` accepts `x_`-prefixed custom properties (required for MITRE ATT&CK, whose objects carry `x_mitre_*` properties) and `--no-strict` skips semantic checks; both map directly to engine options and do not change the report shape.
- **Human output**: one line per finding plus a summary; `--json` replaces it entirely. `--fail-on-warnings` turns SHOULD findings into exit code 1 for CI gates.
- **Distribution, three channels**: (1) a separate PyPI package `stixflayer-cli`, built by maturin with `bindings = "bin"`, so `pip install stixflayer-cli`, `pipx install stixflayer-cli`, or `uv tool install stixflayer-cli` puts the `stixflayer` binary on PATH; (2) `cargo install stixflayer-cli` from crates.io; (3) a `cli-v*` release tag producing static musl Linux binaries (x86_64, aarch64), macOS binaries (x86_64, aarch64), `SHA256SUMS`, and an `install.sh` attached to the release. `install.sh` autodetects OS/architecture, honours `STIXFLAYER_VERSION`, verifies checksums, and installs to `~/.local/bin` by default. Linux and macOS only for now; Windows is out of scope. The library package `stixflayer` on PyPI is unchanged and does not ship the binary — maturin does not support one wheel containing both an extension module and a binary.
- **CLI reference documentation**: a new `docs/cli.md` documents flags, exit codes, the JSON report, and `--print-schema`, so the contract is readable without running `--help`.
- **Release integration**: the existing release gate gains a CLI version/tag entry so a `cli-v*` tag is only cut when the CLI manifest version changes.

## Capabilities

### New Capabilities

- `cli-validation`: how the `stixflayer` binary discovers inputs, classifies documents, parallelises validation, reports results, and signals success or failure.
- `cli-distribution`: how CLI release artifacts are built, named, published, and installed on Linux and macOS, including the checksum and version guarantees `install.sh` relies on.

## Impact

- **New code**: `rust/stixflayer-cli/` (manifest, `main.rs`, report types, input discovery, install/report tests). No engine behaviour changes.
- **New packaging**: `rust/stixflayer-cli/pyproject.toml` for the `stixflayer-cli` wheel (`bindings = "bin"`), published to PyPI alongside the existing `stixflayer` wheel.
- **Modified build**: `rust/Cargo.toml` (workspace members, default features), `pyproject.toml` (`[tool.maturin] features`), `.github/workflows/release.yml` and `.github/scripts/check_release_gate.py` (third release channel), new `install.sh`.
- **Docs**: `docs/cli.md` is added here; the `reposition-python-first` change links it from the README, docs index, and quickstart.
- **Dependencies**: `clap`, `rayon`, and `serde_json` (already present in the workspace) in the CLI crate only. The marketed `stixflayer` crate's dependency set is unchanged.
- **Consumers**: the follow-on GitHub Action that validates public feeds is out of scope; this change makes it possible.
