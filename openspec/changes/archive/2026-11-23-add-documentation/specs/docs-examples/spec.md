# Spec Delta

## Purpose

Guarantees that no documentation example exists which does not compile and run: every Python example shown to users is executed and its printed output verified in CI, and every Rust example in documentation comments runs as a doctest — so documentation stays truthful as the code evolves.

## ADDED Requirements

### Requirement: Python examples in the documentation are executed and output-verified

Every Python code example in the documentation content SHALL be executed in CI. Printed output shown inline with an example SHALL match the output the example actually produces. An example that fails to run, or whose actual output no longer matches its inline output, SHALL fail CI.

#### Scenario: Inline output matches actual output

- **WHEN** CI runs the documentation example tests
- **THEN** each Python example is executed and its inline printed output matches the actual output

#### Scenario: Drifted output fails CI

- **WHEN** a code change alters what a documented example prints
- **THEN** CI fails until the inline output is updated to match

#### Scenario: Non-executable blocks are explicitly marked

- **WHEN** documentation content includes a block that is intentionally not a runnable Python example
- **THEN** that block is marked as non-executable, and any unmarked Python block is executed by the tests

### Requirement: Python examples satisfy the project's lint rules

Every Python code example in the documentation SHALL pass the project's Python lint rules as part of the same CI check.

#### Scenario: Example violating lint fails CI

- **WHEN** a documentation example violates the project's Python lint rules
- **THEN** CI fails with the lint violation identified

### Requirement: README examples are tested

Python code examples in the repository README SHALL be covered by the same execution and output-verification testing as the documentation site content.

#### Scenario: README example runs and is verified

- **WHEN** CI runs the documentation example tests
- **THEN** Python examples in the README are executed and their inline output is verified

### Requirement: Docstring examples are tested when present

Python code examples embedded in docstrings of the public API, when present, SHALL be executed by the same example-testing mechanism as documentation content.

#### Scenario: Docstring example is collected and run

- **WHEN** a public API docstring contains a code example
- **THEN** the example-testing mechanism executes it in CI

### Requirement: Rust documentation examples run as doctests

Code examples in Rust documentation comments on public items SHALL compile and run as doctests, enforced in CI.

#### Scenario: Doctests pass in CI

- **WHEN** CI runs the Rust documentation tests
- **THEN** code examples in documentation comments on public items compile and execute successfully

#### Scenario: Broken doctest fails CI

- **WHEN** a code change breaks a doctest example
- **THEN** CI fails until the example is corrected
