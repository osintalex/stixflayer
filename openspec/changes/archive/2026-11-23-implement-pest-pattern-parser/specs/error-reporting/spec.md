# Spec Delta

## MODIFIED Requirements

### Requirement: Pattern parse failures raise ValidationError with humanized messages

A syntactically invalid STIX pattern SHALL raise `ValidationError` (not the base `StixError`), and
its message SHALL state the line and column of the failure and describe the construct that was
expected, in plain language, without exposing parser-internal debug structures or Rust type paths.

#### Scenario: Invalid pattern raises ValidationError

- **WHEN** `validate_pattern` is called with a string that does not follow the pattern grammar
- **THEN** a `ValidationError` is raised rather than the base `StixError`

#### Scenario: Pattern message contains a position

- **WHEN** an invalid pattern fails to parse
- **THEN** the message states the line and column of the offending input

#### Scenario: Pattern message names the expected construct

- **WHEN** a value, closing delimiter, operator, or keyword is missing
- **THEN** the message names the kind of construct that was expected

#### Scenario: Pattern message contains no parser internals

- **WHEN** an invalid pattern fails to parse
- **THEN** the message describes the syntax problem without Rust debug struct syntax such as
  `Error { input: …, code: … }`, parser error kinds, or `crate::` paths
