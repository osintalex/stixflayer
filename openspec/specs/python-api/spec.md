# python-api Specification

## Purpose

Guarantees the public Python API of stixflayer exposes only intentional, supported entry points and that those entry points are fully typed via `.pyi` stubs, so Python users get a clean, IDE-friendly surface while the Rust engine stays the single implementation underneath.

## Requirements

### Requirement: The public Python API exposes only supported entry points

The `stixflayer` Python package SHALL export only intentional, supported API surface: entry-point functions, object classes and builders, and the documented exception hierarchy. Debug or scratch functions MUST NOT be part of the public API, in either the compiled extension or the stub files.

#### Scenario: Debug function is not part of the public API

- **WHEN** a user imports `stixflayer` and accesses `stixflayer.test_stix`
- **THEN** the attribute does not exist and Python raises `AttributeError`

#### Scenario: Stubs declare no scratch functions

- **WHEN** the `.pyi` stubs shipped in the package are inspected
- **THEN** no debug or scratch function (such as `test_stix`) is declared

### Requirement: Public API entry points are typed via stubs

The package SHALL provide `.pyi` stubs covering its public entry points so that type checkers and IDEs resolve the public API without requiring stub files for every internal module. The project SHALL NOT be required to maintain stubs for every internal.

#### Scenario: Type checker resolves the public API

- **WHEN** a type checker (pyrefly or equivalent) runs over code that uses the documented public API, such as bundle parsing, object classes, and the exception hierarchy
- **THEN** it reports no missing-stub errors for those entry points

#### Scenario: Stubs stay in sync with the compiled surface

- **WHEN** a function, class, or exception is added to or removed from the compiled extension's public surface
- **THEN** the corresponding `.pyi` stubs are updated in the same change
