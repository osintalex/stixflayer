# Design

## Context

See `proposal.md` — Why. The constraints that shape this design:

- `rust/` is a Cargo workspace containing the `stixflayer` library and `stixflayer_derive`. The library currently has `default = ["pyo3"]` and builds a Python extension module through maturin (`pyproject.toml`, `manifest-path = "rust/Cargo.toml"`).
- `pyo3`'s `extension-module` feature is designed for a `cdylib`: it does not link `libpython`, which makes a binary in the same build graph fragile to link.
- The release pipeline already has a version gate (`check_release_gate.py`), per-platform wheel builds, and a `py-v*` / `rust-v*` tag convention.
- Maturin cannot ship an extension module and a binary in one wheel ([maturin#368](https://github.com/PyO3/maturin/issues/368)); `bindings = "bin"` is supported and packages the executable as a wheel script.

## Goals / Non-Goals

**Goals:**
- One command to install on Linux/macOS through PyPI, crates.io, or `install.sh`.
- Validate large single bundles and large directories with all cores.
- A report that can be consumed for years without a breaking change.
- Zero parallelism or CLI dependencies added to the engine crate.

**Non-Goals:**
- Windows support.
- STIX 2.0.
- A GitHub Action wrapper (separate change).
- Parsing JSON itself in parallel (the decoder is serial; objects are parallel).

## Decisions

### D1: A separate `stixflayer-cli` crate in the same workspace

```
rust/
  Cargo.toml                 members = [".", "stixflayer_derive", "stixflayer-cli"]
  src/                       engine (unchanged)
  stixflayer-cli/
    Cargo.toml               stixflayer = { path = "..", default-features = false }
                             [[bin]] name = "stixflayer"
    pyproject.toml           bindings = "bin"
    src/main.rs              clap parsing, pipeline, report
```

The binary is named `stixflayer`; the package is `stixflayer-cli` on both crates.io and PyPI. This keeps `cargo install stixflayer-cli` unambiguous and avoids colliding with the library package name.

*Alternative rejected:* a `[[bin]]` inside the library crate. `cargo install` would build with the `pyo3` default feature, requiring Python headers, and `extension-module` makes binary linking unreliable.

### D2: Flip the library's default features

`rust/Cargo.toml` sets `default = []`; `pyproject.toml` adds `features = ["pyo3"]` under `[tool.maturin]`. Maturin's output is unchanged, while `cargo build -p stixflayer-cli` and `cargo install stixflayer-cli` never enable pyo3.

*Why not `default-features = false` on the dependency alone:* it works for a single-package build, but `cargo build --workspace` unifies features across the workspace and would re-enable pyo3 for the library, risking an `extension-module` link failure for the binary. Flipping the default removes the ambiguity.

### D3: The CLI orchestrates public engine APIs

The CLI reads files and drives validation; it does not reimplement any check:

```rust
let doc: Value = serde_json::from_str(&text)?;
// bundle: validate each object, then run bundle invariants
let outcomes: Vec<_> = doc["objects"]
    .as_array()
    .par_iter()
    .map(|v| StixObject::from_value_outcome(v.clone(), true, true))
    .collect();
let bundle = Bundle { object_type, id, objects };
bundle.check_invariants();
```

Bundle invariants run only when object errors are empty, matching `Bundle::from_json_outcome`. A single integration test asserts the CLI's verdict equals `Bundle::from_json_outcome` for every fixture in `testdata/test_matrix.json`; the CLI's internal assembly order is not otherwise constrained.

*Alternative rejected:* a `parallel` feature inside the engine. It would put rayon in the marketed Rust crate and couple the engine to one consumer's execution model.

### D4: Report types live in the CLI and reuse `Entry`

```rust
struct Report { schema_version: u32, summary: Summary, results: Vec<FileResult>, skipped: Vec<Skipped> }
struct FileResult { path: String, valid: bool, errors: Vec<Entry>, warnings: Vec<Entry> }
struct Skipped { path: String, reason: String }
```

`Outcome` is not serialized directly: `Outcome<Bundle>` carries the parsed document in `value`, which must never appear in the report. The CLI maps the outcome to `valid/errors/warnings` and drops the value.

A checked-in JSON Schema (`schema/report.schema.json`) is printed by `--print-schema`; a test validates a mixed report against it. The schema is hand-written rather than generated from the Rust types so the contract cannot drift with an internal refactor. `schema_version` stays `1`; evolution is additive.

### D5: Classification and exit codes

Classification is decided before validation, from the parsed top-level value:

```
parse fails, ext in {.stix2,.stix}   -> invalid (deserialization_error)
parse fails, ext == .json            -> skipped: not_json
no `type` string                     -> skipped: not_stix
`spec_version` != "2.1"              -> skipped: unsupported_spec_version
otherwise                            -> validate
```

`.jsonl` files are split into non-empty lines and each line runs through the
same classification. A malformed line is invalid with a `deserialization_error`
that names the line; a file whose lines are all skipped is skipped as
`not_stix`; skipped lines in a file with at least one validated line do not
affect the file's verdict.

Reasons are free-form strings; only `results` has a frozen shape. Exit codes: 0 all valid, 1 any invalid (or any warning under `--fail-on-warnings`), 2 usage/I/O. `unreadable` is never a skip.

### D6: Parallelism and ordering

Read every input, then run a nested rayon traversal: `par_iter` over files, `par_iter` over each file's objects. Rayon's work-stealing means a single 53 MB bundle still uses all cores; `-j` maps to `ThreadPoolBuilder::num_threads` (`0` means default). Paths are sorted before dispatch and `collect` preserves input order, so the report is deterministic at any job count. The JSON decoder itself is serial; only object validation is parallel.

### D7: Three install channels, one binary

- **PyPI**: `rust/stixflayer-cli/pyproject.toml` with `bindings = "bin"`, published as `stixflayer-cli`. The wheel contains only the executable, so it does not shadow the `stixflayer` module.
- **crates.io**: publish `stixflayer-cli`; the dependency on `stixflayer` uses `default-features = false`.
- **Direct**: static musl Linux and macOS archives plus `install.sh`, attached to the release so `https://github.com/osintalex/stixflayer/releases/latest/download/install.sh` is a stable URL.

`install.sh` maps `uname -s`/`uname -m` to a target triple, honours `STIXFLAYER_VERSION`, verifies `SHA256SUMS`, and installs to `${STIXFLAYER_INSTALL_DIR:-$HOME/.local/bin}`. Static musl avoids glibc-version failures on old runners and slim containers.

### D8: Release gating reuses the existing mechanism

`check_release_gate.py` gains a `--manifest rust/stixflayer-cli/Cargo.toml --tag-prefix cli-v` invocation. The CLI job builds the four targets, runs the binary against a fixture, publishes to PyPI and crates.io, uploads assets, and tags. The CLI version is independent of the library version.

## Risks / Trade-offs

- **Two PyPI package names could confuse users** → documentation states both commands on the first screen; the binary is always `stixflayer`, so scripts never depend on the package name.
- **Wheel size and platform matrix grow by four builds** → wheels are platform-specific and small (no Python module); reuse the existing release matrix pattern.
- **A 53 MB bundle materialises as a large `Value` tree** → one file's tree at a time per worker; document memory expectations rather than streaming in this change.
- **CLI assembly could drift from engine semantics** → one integration test over `testdata/test_matrix.json` asserts equal verdicts; the CLI never reimplements a check.
- **Feature unification could re-enable pyo3 in workspace builds** → D2 removes the default; CI builds the CLI with `--locked` and no default features.
- **`--print-schema` could drift from the code** → the schema is checked in and a test validates a real report against it.

## Migration Plan

Additive: new crate, new package, new release channel. The library wheel and crate are unchanged in content; only their default feature set moves behind maturin. Rollback is deleting the new release job and package; no user data or API is affected.

## Open Questions

None that affect the specs, approach, or task breakdown.
