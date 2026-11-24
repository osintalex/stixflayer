# cli-validation Specification

## Purpose
Defines how the `stixflayer` command discovers STIX documents, classifies them, validates them in parallel, and reports the outcome, so CI systems and analysts can gate on STIX validity without writing code.

## Requirements

### Requirement: Input discovery

The CLI SHALL accept one or more path arguments. A file path SHALL be validated regardless of its extension. A directory path SHALL be walked recursively, selecting only files whose extension is `.json`, `.jsonl`, `.stix2`, or `.stix`. The argument `-` SHALL read a single document from standard input.

#### Scenario: Directory scan selects STIX extensions

- **WHEN** the CLI is given a directory containing `feed.stix2`, `feed.jsonl`, `bundle.json`, `notes.md`, and `config.yaml`
- **THEN** it validates `feed.stix2`, `feed.jsonl`, and `bundle.json` and ignores the other two files entirely

#### Scenario: Explicit path overrides the extension filter

- **WHEN** the CLI is given an explicitly named file whose extension is not one of the recognised three
- **THEN** the file is still validated

#### Scenario: Standard input

- **WHEN** the CLI is invoked with `-`
- **THEN** it reads one document from standard input and reports it under the path `-`

### Requirement: Document classification

Every candidate document SHALL be classified as valid, invalid, or skipped. A skipped document SHALL carry a free-form `reason`; the CLI MUST NOT reject a run because of a skip. A file that cannot be read SHALL be reported as an operational failure and MUST NOT be silently skipped. A `.jsonl` file SHALL be treated as one JSON document per non-empty line, with each line classified independently.

#### Scenario: JSON without a STIX type is skipped

- **WHEN** a discovered `.json` file parses as JSON but has no STIX `type` value
- **THEN** it appears under `skipped` with reason `not_stix` and does not affect the exit code

#### Scenario: Unparseable JSON file is skipped

- **WHEN** a discovered `.json` file is not valid JSON
- **THEN** it appears under `skipped` with reason `not_json` and does not affect the exit code

#### Scenario: Unparseable STIX-extension file is invalid

- **WHEN** a discovered `.stix2` or `.stix` file is not valid JSON
- **THEN** it is classified as invalid with a `deserialization_error` entry

#### Scenario: STIX 2.0 is skipped, not rejected

- **WHEN** a document declares `spec_version` other than `2.1`
- **THEN** it appears under `skipped` with reason `unsupported_spec_version`

#### Scenario: Unreadable file fails the run

- **WHEN** a discovered file exists but cannot be read
- **THEN** the CLI reports the error on standard error and exits with code 2

#### Scenario: JSON Lines file validates each line

- **WHEN** a `.jsonl` file contains two valid STIX objects on separate lines
- **THEN** the file is valid and its object count is 2

#### Scenario: Malformed JSON Lines entry is invalid

- **WHEN** a `.jsonl` file has a valid line followed by a line that is not valid JSON
- **THEN** the file is invalid with a `deserialization_error` that names the failing line

#### Scenario: JSON Lines file with no STIX is skipped

- **WHEN** every non-empty line of a `.jsonl` file parses as JSON but none has a STIX `type`
- **THEN** the file appears under `skipped` with reason `not_stix` and does not affect the exit code

### Requirement: Object-level parallelism

The CLI SHALL validate objects in parallel, using all logical cores by default. `-j` / `--jobs` SHALL set the worker count. The report MUST NOT depend on the worker count: the same inputs SHALL produce identical output at any job setting, ordered by path.

#### Scenario: Output is independent of job count

- **WHEN** the same directory is validated with `-j 1` and with `-j 8`
- **THEN** the two JSON reports are byte-identical

#### Scenario: A single large bundle uses object-level parallelism

- **WHEN** one bundle containing thousands of objects is the only input
- **THEN** its objects are validated in parallel rather than serially per file

### Requirement: Stable JSON report

`--json` SHALL write a single JSON document containing `schema_version`, `summary`, `results`, and `skipped`. Each `results` entry SHALL contain `path`, `valid`, `errors`, and `warnings`, where the two lists use the engine's entry shape. The report MUST NOT contain the parsed STIX document. After the initial release the report SHALL evolve by adding fields only.

#### Scenario: Valid and invalid documents appear in one report

- **WHEN** a run covers one valid and one invalid document
- **THEN** `results` contains one entry per document with the correct `valid` value, and `summary` counts one of each

#### Scenario: Report does not echo the document

- **WHEN** a valid bundle is reported
- **THEN** its `results` entry contains no `objects`, `value`, or other parsed document content

#### Scenario: Schema version is present and stable

- **WHEN** any run produces a JSON report
- **THEN** `schema_version` is the integer `1`

### Requirement: JSON Schema is discoverable

`--print-schema` SHALL write a JSON Schema describing the report to standard output and exit successfully without validating any input.

#### Scenario: Printed schema describes the report

- **WHEN** the CLI is run with `--print-schema` and no paths
- **THEN** it prints a JSON Schema document and exits 0

#### Scenario: Real reports validate against the printed schema

- **WHEN** a report from a run containing valid, invalid, and skipped documents is validated against the printed schema
- **THEN** validation succeeds

### Requirement: Exit codes

The CLI SHALL exit `0` when every validated document is valid, `1` when at least one document is invalid, and `2` for usage or I/O failures. Skips MUST NOT cause a non-zero exit. `--fail-on-warnings` SHALL cause exit `1` when any warning is reported.

#### Scenario: All valid

- **WHEN** every validated document is valid
- **THEN** the exit code is 0

#### Scenario: Any invalid

- **WHEN** at least one document is invalid
- **THEN** the exit code is 1

#### Scenario: Only skips

- **WHEN** all discovered documents are skipped and none are invalid
- **THEN** the exit code is 0

#### Scenario: Usage error

- **WHEN** a path argument does not exist
- **THEN** the CLI reports the problem and exits 2

#### Scenario: Warnings gate

- **WHEN** `--fail-on-warnings` is set and a document produces only warnings
- **THEN** the exit code is 1

### Requirement: Custom properties are accepted by default

The CLI SHALL accept and validate custom properties without requiring a flag, because STIX 2.1 permits them. Custom-property names and suffix rules SHALL still be enforced. The report shape MUST NOT change.

#### Scenario: ATT&CK-style custom properties

- **WHEN** a document contains `x_mitre_*` properties
- **THEN** the document validates without `unknown_property` errors

#### Scenario: Invalid custom-property names are still rejected

- **WHEN** a document contains a custom property whose name violates the STIX 2.1 custom-property rules
- **THEN** validation reports the corresponding error

### Requirement: Human-readable output

Without `--json`, the CLI SHALL print one line per finding, including the path and the object id when known, followed by a summary of counts. With `--json`, it SHALL print only the JSON report.

#### Scenario: Findings name the file

- **WHEN** a document is invalid
- **THEN** the human output includes the file path and the finding message

#### Scenario: JSON suppresses human output

- **WHEN** `--json` is set
- **THEN** standard output contains only the JSON report
