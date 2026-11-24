# Spec Delta

## Purpose

Defines the quality bar for the published Rust crates' API documentation on docs.rs: builds succeed, crate-level introductions are accurate and runnable, binding-internal modules stay out of the rendered docs, the user-facing public surface is documented and enforced in CI, and the derive crate is documented.

## ADDED Requirements

### Requirement: Published crates build their API documentation

The `stixflayer` and `stixflayer_derive` crates SHALL produce successful API documentation builds on every release.

#### Scenario: Docs are available after release

- **WHEN** a Rust crate release is published
- **THEN** the rendered API documentation for that release is available for both crates

### Requirement: Crate-level introduction is accurate and runnable

Each crate's top-level documentation SHALL describe the library's current, released functionality without work-in-progress framing. The `stixflayer` crate's introduction SHALL include a quick-start example that runs as a doctest.

#### Scenario: Introduction reflects released functionality

- **WHEN** the published API documentation landing page is viewed
- **THEN** the introduction describes what the released crate does, with no "work in progress" framing

#### Scenario: Crate-level quick-start runs

- **WHEN** doctests are run
- **THEN** the quick-start example in the crate-level documentation executes successfully

### Requirement: Binding-internal modules are excluded from rendered docs

Modules that exist to serve other language bindings and are not part of the Rust user-facing API SHALL be excluded from the rendered API documentation.

#### Scenario: Binding plumbing does not appear in docs

- **WHEN** the rendered API documentation lists the crate's modules
- **THEN** the Python-binding plumbing modules are not presented as part of the Rust user API

### Requirement: User-facing public surface is documented and enforced

Public items of the crate's user-facing API SHALL carry documentation comments, and CI SHALL fail when a user-facing public item is undocumented. The enforced scope is defined in the design.

#### Scenario: Undocumented public item fails CI

- **WHEN** a public item in the user-facing API is added or changed without documentation
- **THEN** CI fails until documentation is added

#### Scenario: Current user-facing surface passes

- **WHEN** CI runs the documentation enforcement
- **THEN** all public items in the enforced user-facing scope are documented

### Requirement: Derive crate is documented

The `stixflayer_derive` crate SHALL have a crate-level introduction, and each public macro SHALL be documented with a usage example that runs as a doctest.

#### Scenario: Macro documentation includes a working example

- **WHEN** the derive crate's macro documentation is viewed or its doctests are run
- **THEN** each public macro is documented with a usage example that executes successfully
