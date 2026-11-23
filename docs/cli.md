# Command-line interface

The `stixflayer` binary validates STIX 2.1 files, directories, and standard
input without Python or a Rust toolchain. It is a thin, parallel front end to
the same engine that powers the Python and Rust packages, so its verdicts match
the library exactly.

## Install

### PyPI (recommended)

```console
pip install stixflayer-cli
```

`pipx` and `uv` work too:

```console
pipx install stixflayer-cli
uv tool install stixflayer-cli
```

The wheel installs only the `stixflayer` executable. It does not install a
Python module, so it coexists with the `stixflayer` library package.

### crates.io

```console
cargo install stixflayer-cli
```

The CLI crate builds without the library's Python bindings, so Python headers
are not required.

### Direct download

Linux and macOS users can install a release archive with the install script:

```console
curl -LsSf https://github.com/osintalex/stixflayer/releases/latest/download/install.sh | sh
```

The script detects the host OS and architecture, verifies the archive against
`SHA256SUMS`, and installs to `~/.local/bin` by default. Set
`STIXFLAYER_VERSION` to pin a version and `STIXFLAYER_INSTALL_DIR` to choose a
different directory. Windows is not supported.

## Usage

```console
stixflayer [OPTIONS] <PATH>...
```

Each `PATH` is a file or directory. Directories are walked recursively and only
files ending in `.json`, `.jsonl`, `.stix2`, or `.stix` are selected. An
explicitly named file is validated regardless of its extension. Use `-` to read
one document from standard input.

```console
stixflayer testdata/stix/valid/bundle.json
stixflayer testdata/stix/valid
cat testdata/stix/valid/bundle.json | stixflayer -
```

### Options

| Option | Description |
| --- | --- |
| `-j`, `--jobs <N>` | Worker threads. `0` (the default) uses every logical core. |
| `--json` | Write the machine-readable report instead of human-readable output. |
| `--print-schema` | Print the JSON Schema for the report and exit without validating. |
| `--allow-custom` | Accept custom properties such as ATT&CK's `x_mitre_*` fields. |
| `--no-strict` | Skip semantic (SHOULD-level) checks and report only structural errors. |
| `--fail-on-warnings` | Exit `1` when any warning is reported. |
| `-h`, `--help` | Print usage. |
| `-V`, `--version` | Print the crate version. |

Validation runs on objects in parallel. The report is ordered by path, so the
same inputs produce the same output at any `--jobs` setting.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every validated document is valid. Skipped documents do not affect the code. |
| `1` | At least one document is invalid, or a warning was reported with `--fail-on-warnings`. |
| `2` | Usage error, missing path, unreadable file, or another I/O failure. |

```console
stixflayer testdata/stix/valid/bundle.json; echo $?
```

```console
0
```

An invalid document exits `1`:

```console
stixflayer testdata/stix/invalid/sdo/identity-no-name.json; echo $?
```

```console
1
```

A missing path exits `2`:

```console
stixflayer does-not-exist.json; echo $?
```

```console
2
```

### Skips

Some files are intentionally not validated. They appear under `skipped` with a
free-form reason and never change the exit code:

| Reason | Meaning |
| --- | --- |
| `not_json` | A `.json` file that is not valid JSON. |
| `not_stix` | Valid JSON without a STIX `type` string. |
| `unsupported_spec_version` | A document whose `spec_version` is not `2.1`. |

A `.stix2` or `.stix` file that is not valid JSON is **invalid** (it has a
`deserialization_error`), not skipped. A file that exists but cannot be read is
an operational failure and exits `2`.

### JSON Lines

A `.jsonl` file is read as one JSON document per non-empty line. Each line is
classified independently, so a feed can mix STIX objects and non-STIX records.
Parse or validation failures make the file invalid and name the line:

```text
feed.jsonl: error [deserialization_error] line 3: expected value at line 1 column 1
```

If every line is non-STIX, the file is skipped as `not_stix`. Lines that are
skipped do not change the exit code. `summary.objects` counts the objects
validated across all lines.

## Human-readable output

Without `--json`, each finding is printed on one line with its path, kind, and
object id when known, followed by a summary:

```console
stixflayer testdata/stix/invalid/sdo/indicator-no-valid-from.json
```

```text
testdata/stix/invalid/sdo/indicator-no-valid-from.json: error [missing_property] (indicator--6f1e2d3c-4b5a-4968-8776-5a4b3c2d1e0f) `indicator` is missing required property 'valid_from'
1 files: 0 valid, 1 invalid, 0 skipped; 1 objects, 1 errors, 0 warnings
```

## JSON report

`--json` writes a single JSON document and suppresses all human-readable output:

```console
stixflayer --json testdata/stix/valid/bundle.json
```

```json
{
  "schema_version": 1,
  "summary": {
    "files": 1,
    "valid": 1,
    "invalid": 0,
    "skipped": 0,
    "objects": 2,
    "errors": 0,
    "warnings": 0
  },
  "results": [
    {
      "path": "testdata/stix/valid/bundle.json",
      "valid": true,
      "errors": [],
      "warnings": []
    }
  ],
  "skipped": []
}
```

Each `results` entry contains `path`, `valid`, `errors`, and `warnings`. Errors
and warnings use the engine's stable entry shape (`kind`, `message`, and
optional `property`, `value`, `vocabulary`, and `object_id`). The report never
echoes the parsed STIX document.

`summary.files` counts validated and skipped inputs, `summary.objects` counts
the STIX objects that were validated, and `summary.errors` / `summary.warnings`
count the findings in the same report.

### Report schema

`--print-schema` prints the checked-in JSON Schema for the report and exits `0`
without reading any input:

```console
stixflayer --print-schema
```

The schema lives at
[`rust/stixflayer-cli/schema/report.schema.json`](https://github.com/osintalex/stixflayer/blob/main/rust/stixflayer-cli/schema/report.schema.json).
`schema_version` is `1`; after the initial release the report evolves by adding
fields only.

## CI example

Gate a repository's STIX files in a GitHub Actions job. From a checkout of
this repository, the command runs against the bundled fixtures:

```yaml
- name: Validate STIX
  run: stixflayer --json --fail-on-warnings testdata/stix/valid/bundle.json
```

Use `--allow-custom` for ATT&CK-style documents whose objects carry
`x_mitre_*` properties, and `--no-strict` when only structural errors should
fail the run.
