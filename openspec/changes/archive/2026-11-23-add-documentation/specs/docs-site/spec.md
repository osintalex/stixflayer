# Spec Delta

## Purpose

Defines the public documentation website for stixflayer: what it covers, how versions are published and selected, and the quality gates every deploy passes — so Python developers get a current, navigable, concise documentation site, and Rust developers are routed to the Rust crates' API documentation instead.

## ADDED Requirements

### Requirement: Public documentation site serves the Python package

The project SHALL publish a documentation website at a stable public URL documenting the Python package's installation and usage. For the Rust crates' API reference, the site SHALL link to the crates' published API documentation rather than duplicating it.

#### Scenario: Site root serves Python documentation

- **WHEN** a visitor opens the documentation site root
- **THEN** the documentation for the current stable Python version is served, including installation instructions

#### Scenario: Rust API reference is delegated, not duplicated

- **WHEN** the site presents where to find the Rust API reference
- **THEN** it links to the Rust crates' published API documentation instead of reproducing it

### Requirement: Getting-started path works end to end

The site SHALL provide a getting-started path that takes a new user from installation to parsing and validating a first STIX document and handling a validation failure, using code examples that are executed and verified (see the tested-examples capability).

#### Scenario: A new user follows the quickstart

- **WHEN** a user follows the getting-started page from top to bottom
- **THEN** they install the package, parse a STIX document, and handle a validation failure using code shown on that page

### Requirement: Documentation is versioned with a version selector

The site SHALL maintain a version selector offering: a `dev` version that tracks the main branch; one entry per stable Python minor release (for example `0.1`, `0.2`); and a `latest` alias that resolves to the most recent stable version. The site root SHALL serve the `latest` version by default.

#### Scenario: New stable version appears in the selector

- **WHEN** a stable Python release is published
- **THEN** a version entry for that minor version exists in the selector and the `latest` alias resolves to it

#### Scenario: Root serves latest

- **WHEN** a visitor opens the site root
- **THEN** they are served the version the `latest` alias points to

#### Scenario: Dev tracks main

- **WHEN** documentation content changes on main and deploys
- **THEN** the `dev` version reflects that content

### Requirement: Versioned deploys are gated on successful release

A new documentation version snapshot SHALL be published only after the corresponding Python package publish succeeds, and the published snapshot SHALL correspond to the released code.

#### Scenario: Publish success publishes the version

- **WHEN** a Python package publish completes successfully
- **THEN** a documentation snapshot for that version is published

#### Scenario: Publish failure blocks the version

- **WHEN** the Python package publish fails
- **THEN** no new documentation version entry is published

### Requirement: Documentation builds are enforced in CI

Every documentation change SHALL be validated by a strict site build in CI that fails on broken internal links and build errors before merge.

#### Scenario: Broken internal link fails CI

- **WHEN** a pull request introduces a broken internal documentation link
- **THEN** the documentation build job fails

### Requirement: Machine-readable documentation index is generated

The site build SHALL produce a machine-readable `llms.txt` index of the documentation at the site root.

#### Scenario: Build produces llms.txt

- **WHEN** the documentation site is built
- **THEN** the build output includes an `llms.txt` file at the site root
