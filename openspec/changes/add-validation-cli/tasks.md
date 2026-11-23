# Tasks

## 1. Workspace and build split

- [x] 1.1 Create `rust/stixflayer-cli/Cargo.toml` and `src/main.rs` with a minimal `main`, add `"stixflayer-cli"` to the workspace members, and set `stixflayer = { path = "..", default-features = false }` with `[[bin]] name = "stixflayer"`; verify `cargo metadata --no-deps` lists the crate and `cargo build -p stixflayer-cli` succeeds.
- [x] 1.2 Set `default = []` in `rust/Cargo.toml` and add `features = ["pyo3"]` under `[tool.maturin]` in `pyproject.toml`; verify `cargo tree -p stixflayer-cli | grep -c pyo3` prints `0` and `uv run maturin develop --release` still builds and imports.
- [x] 1.3 Add `clap` and `rayon` to the CLI crate only and verify `cargo tree -p stixflayer` shows neither.

## 2. CLI surface

- [x] 2.1 Define the clap interface: positional paths, `-j/--jobs`, `--json`, `--print-schema`, `--allow-custom`, `--no-strict`, `--fail-on-warnings`, `--version`; verify `stixflayer --help` lists every flag and `stixflayer --version` prints the crate version.
- [x] 2.2 Make paths optional only when `--print-schema` is set and verify `stixflayer` with no arguments exits 2 with a usage message.
- [x] 2.3 Map `-j 0` to the rayon default and verify `stixflayer -j 0 <fixture>` behaves identically to omitting `-j`.

## 3. Discovery and classification

- [x] 3.1 Implement recursive directory walking with the `.json`, `.jsonl`, `.stix2`, `.stix` filter, explicit-path bypass, and `-` for stdin; verify unit tests cover a mixed directory, an explicit `.txt` path, and stdin.
- [x] 3.2 Implement classification (`not_json`, `not_stix`, `unsupported_spec_version`, invalid STIX-extension parse failures, unreadable files) per the spec; verify unit tests for each of the five cases, including exit code 2 for an unreadable file.
- [x] 3.3 Verify a `.json` file that parses but has no `type` lands in `skipped` with `not_stix` and does not change the exit code.
- [x] 3.4 Support `.jsonl` input as one JSON document per non-empty line, classify each line independently, name the failing line in `deserialization_error` messages, skip files whose lines are all non-STIX, and verify unit and integration tests for valid, malformed, and all-skipped JSON Lines files.

## 4. Parallel validation pipeline

- [x] 4.1 Read every input, then validate objects with nested rayon traversal, build the `Bundle`, and run `check_invariants` only when object errors are empty; verify the CLI verdict for every fixture in `testdata/test_matrix.json` equals `Bundle::from_json_outcome` in an integration test.
- [x] 4.2 Sort paths before dispatch and verify the JSON report is byte-identical for `-j 1` and `-j 8` over `testdata/stix/`.
- [x] 4.3 Verify a single multi-thousand-object bundle is validated without requiring multiple input files (use `testdata/stix/valid/bundle.json` scaled up by a generated fixture, or the ATT&CK file in 10.2).

## 5. Report and schema

- [x] 5.1 Implement `Report`, `FileResult`, `Skipped`, and `Summary` with `schema_version: 1`, reusing `Entry` for errors and warnings; verify a JSON snapshot contains the four top-level keys and no `objects` or `value` field.
- [x] 5.2 Check in `schema/report.schema.json` and implement `--print-schema`; verify the printed schema is valid JSON, exits 0 with no paths, and validates a report containing valid, invalid, and skipped documents using a JSON Schema dev-dependency.
- [x] 5.3 Verify the summary counts (files, valid, invalid, skipped, objects, errors, warnings) match the `results` and `skipped` arrays in the same report.

## 6. Exit codes and human output

- [x] 6.1 Implement exit codes 0/1/2 and `--fail-on-warnings`; verify integration tests with `assert_cmd` for all-valid, any-invalid, skips-only, missing-path, and warnings-only cases.
- [x] 6.2 Implement human output as one line per finding with path and `object_id` when present, plus a summary; verify a snapshot for an invalid fixture and that `--json` prints only the JSON document.

## 7. PyPI packaging

- [x] 7.1 Add `rust/stixflayer-cli/pyproject.toml` with `bindings = "bin"`, build a wheel with `maturin build`, install it into a clean venv, and verify `stixflayer --version` runs from that venv's `bin`.
- [x] 7.2 Verify the CLI wheel installs no `stixflayer` Python module (`python -c "import stixflayer"` fails in a venv containing only the CLI wheel), and that installing both wheels yields a working `import stixflayer` plus a working `stixflayer --version`.

## 8. Release artifacts and install.sh

- [x] 8.1 Extend `.github/scripts/check_release_gate.py` usage with a `cli-v` channel for `rust/stixflayer-cli/Cargo.toml`; verify the gate reports "release" on a bumped version and "skip" on an unchanged one using local dry runs.
- [x] 8.2 Add the CLI release job to `.github/workflows/release.yml` building `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`, publishing to PyPI and crates.io, uploading the four archives plus `SHA256SUMS` and `install.sh`, and tagging `cli-v<version>`; verify the workflow parses with `actionlint` or the GitHub workflow schema check used by the project.
- [x] 8.3 Write `install.sh` with OS/architecture detection, `STIXFLAYER_VERSION`, `STIXFLAYER_INSTALL_DIR`, checksum verification, and an unsupported-platform error; verify with shellcheck plus scripted tests for a successful Linux x86_64 install, a pinned version, a checksum mismatch, and an unsupported OS.
- [x] 8.4 Verify the Linux artifacts are statically linked (`file` or `ldd` reports "not a dynamic executable") so they run on Alpine and old glibc hosts.

## 9. CLI reference documentation

- [x] 9.1 Write `docs/cli.md` covering install (all three channels), usage, flags, exit codes, the JSON report, `--print-schema`, and the skip reasons; add `- CLI: cli.md` to the `mkdocs.yml` nav and verify the docs build succeeds.
- [x] 9.2 Verify every command shown in `docs/cli.md` runs as written against `testdata/stix/valid/bundle.json` and produces the documented exit code.

## 10. Integration verification

- [x] 10.1 Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` from `rust/`; verify all pass.
- [ ] 10.2 Validate MITRE ATT&CK's `enterprise-attack.json` (download to a temp directory, do not commit) with `--allow-custom`; verify the run completes, reports a valid document, and record wall-clock time and peak memory in the change's review notes.
- [x] 10.3 Re-run the Amnesty and MVT feeds from `fix-validation-correctness` task 6.3 through the CLI; verify Amnesty exits 0 and MVT exits 0 (or 1 only under `--fail-on-warnings`) and record the counts.
- [x] 10.4 Run `uv run ruff check .`, `uv run pyrefly check`, and `uv run pytest`; verify all pass.

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- Run the first `cli-v*` release end to end and verify the `releases/latest/download/install.sh` URL resolves.
- The GitHub Action that wraps the CLI for other repositories is a separate change.
