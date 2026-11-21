# Spec Delta

## ADDED Requirements

### Requirement: Validation outcomes are exposed through warnings and check

Objects returned by constructors and `from_json` SHALL expose a `.warnings` list. Exceptions SHALL expose both `.errors` and `.warnings`. A non-raising `check()` entry point SHALL return the raw outcome with `valid`, `errors`, and `warnings`.

#### Scenario: Object exposes warnings

- **WHEN** an object with a SHOULD finding is constructed
- **THEN** the returned object has a `.warnings` list containing the finding

#### Scenario: Exception exposes warnings

- **WHEN** validation raises for a MUST violation and also collected a SHOULD finding
- **THEN** the exception has `.errors` and `.warnings`

#### Scenario: check returns the raw outcome

- **WHEN** `check()` is called with valid input that has a SHOULD finding
- **THEN** it returns an outcome whose `valid` is true, `errors` is empty, and `warnings` contains the finding, without raising

#### Scenario: check returns errors without raising

- **WHEN** `check()` is called with input that violates a MUST requirement
- **THEN** it returns an outcome whose `valid` is false and `errors` is non-empty, without raising

## MODIFIED Requirements

### Requirement: Public API entry points are typed via stubs

The package SHALL provide `.pyi` stubs covering its public entry points so that type checkers and IDEs resolve the public API without requiring stub files for every internal module. The project SHALL NOT be required to maintain stubs for every internal.

#### Scenario: Type checker resolves the public API

- **WHEN** a type checker (pyrefly or equivalent) runs over code that uses the documented public API, such as bundle parsing, object classes, and the exception hierarchy
- **THEN** it reports no missing-stub errors for those entry points

#### Scenario: Stubs stay in sync with the compiled surface

- **WHEN** a function, class, or exception is added to or removed from the compiled extension's public surface
- **THEN** the corresponding `.pyi` stubs are updated in the same change

#### Scenario: Stubs declare warnings and check

- **WHEN** the shipped stubs are inspected
- **THEN** object classes declare `warnings`, the exception hierarchy declares `warnings`, and `check` is declared with its outcome return type
