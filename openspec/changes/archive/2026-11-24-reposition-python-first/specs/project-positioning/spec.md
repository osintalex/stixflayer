# Spec Delta

## Purpose

Keeps the project's public story consistent with what it actually ships: one Python-first positioning statement, quantitative claims that trace to a committed benchmark, registry-specific READMEs for PyPI and crates.io, and concise documentation with no aspirational language roadmap.

## ADDED Requirements

### Requirement: One positioning statement

The README, docs site metadata, docs index, and package descriptions SHALL present stixflayer as a Python-first STIX 2.1 library powered by a Rust engine, with a native CLI for file validation. They MUST NOT describe the project as a polyglot implementation or advertise bindings for languages that are not shipped.

#### Scenario: No roadmap languages in shipped docs

- **WHEN** the shipped documentation is searched for TypeScript, JavaScript, Go, Java, WASM, Extism, or napi
- **THEN** no match presents them as a current or planned binding

#### Scenario: Positioning is identical across entry points

- **WHEN** the README tagline, `mkdocs.yml` `site_description`, and `docs/index.md` introduction are compared
- **THEN** each states the Python-first positioning and none claims "consumed by many languages"

### Requirement: Quantitative claims are reproducible

Every performance number in the README and docs SHALL be derived from `benchmarks/BENCHMARKING.md`, and the same fixture SHALL NOT be quoted with different speedups in different files.

#### Scenario: Speedup matches the canonical table

- **WHEN** the README quotes a speedup for a benchmark fixture
- **THEN** the value matches the ratio in `benchmarks/BENCHMARKING.md` for that fixture

#### Scenario: No unreproducible range

- **WHEN** the docs quote a speedup range
- **THEN** both bounds are supported by entries in `benchmarks/BENCHMARKING.md`

### Requirement: README is concise

The GitHub README SHALL be at most 100 lines and SHALL contain the positioning statement, `pip install` instructions, CLI install instructions, a short usage example, and links to the guides and API reference. Detailed conformance notes MUST live in the docs site, not the README.

#### Scenario: Length budget

- **WHEN** `README.md` is measured
- **THEN** it is 100 lines or fewer

#### Scenario: Both install paths present

- **WHEN** a reader opens the README
- **THEN** it shows the `pip install` command and the CLI install command

#### Scenario: Conformance notes are not in the README

- **WHEN** the README is inspected
- **THEN** it links to the conformance page instead of listing individual spec findings

### Requirement: Registry-specific READMEs

The crates.io package SHALL use a Rust-focused README that documents `cargo add stixflayer`, the crate's API, and the CLI crate, while the GitHub README addresses Python users. Each README SHALL be accurate for the registry that renders it.

#### Scenario: crates.io renders the Rust README

- **WHEN** the crate manifest is packaged
- **THEN** its `readme` field points to the Rust-focused README

#### Scenario: Rust users can find the crate entry point

- **WHEN** a Rust user reads the crates.io README
- **THEN** it shows the dependency line and a minimal parse example

### Requirement: CLI is discoverable from the main docs

The README, docs index, and quickstart SHALL link to the CLI reference and SHALL show at least one CLI validation command.

#### Scenario: README links the CLI reference

- **WHEN** a reader looks for CLI usage
- **THEN** the README links to the CLI reference page

#### Scenario: Quickstart shows a CLI command

- **WHEN** a reader follows the quickstart
- **THEN** it includes a command that validates a STIX file and states the exit-code meaning

### Requirement: Documentation examples still execute

Edits to documentation code blocks SHALL preserve the executable-example contract: Python blocks keep their `#>` expected-output markers and continue to pass the docs example test suite.

#### Scenario: Docs example suite passes

- **WHEN** the documentation example tests run after the rewrite
- **THEN** every Python block executes and produces its documented output
