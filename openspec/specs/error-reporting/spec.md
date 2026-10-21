# error-reporting Specification

## Purpose

Defines how stixflayer reports validation failures to Python callers: which exception type each failure raises, the structured `.errors` entries every exception carries, and the quality bar for human-readable messages — so callers can catch invalid input reliably and present clear errors to their users.

## Requirements

### Requirement: Exceptions always carry structured error entries

Every exception raised by the library SHALL expose a non-empty `.errors` list containing at least one structured entry with `kind` and `message` fields, regardless of failure type.

#### Scenario: Vocabulary failure carries an entry

- **WHEN** constructing an object with a value outside a defined vocabulary
- **THEN** the raised exception's `.errors` list contains at least one entry with a `kind` and `message`

#### Scenario: Deserialization failure carries an entry

- **WHEN** parsing input that is not valid JSON
- **THEN** the raised exception's `.errors` list contains at least one entry with a `kind` and `message`

### Requirement: Vocabulary violations produce structured entries

Failures caused by a value outside a defined vocabulary SHALL produce an entry whose `kind` identifies a vocabulary violation and which includes the rejected value and the vocabulary name as fields.

#### Scenario: Invalid vocabulary value includes context

- **WHEN** an object is constructed with a sophistication value not in the threat-actor sophistication vocabulary
- **THEN** the `.errors` entry includes the rejected value and the vocabulary name as structured fields

### Requirement: Nested validation messages use a single prefix

When a validation failure message incorporates an inner failure's message, the combined message SHALL contain the `STIX validation error:` prefix at most once.

#### Scenario: Vocabulary failure inside an object-level failure

- **WHEN** an object fails validation because one of its vocabulary values is invalid
- **THEN** the exception message names the object and the underlying cause with the prefix appearing only once

### Requirement: Pattern parse failures raise ValidationError with humanized messages

A syntactically invalid STIX pattern SHALL raise `ValidationError` (not the base `StixError`), and its message SHALL describe the failure in plain language without exposing parser-internal debug structures.

#### Scenario: Invalid pattern raises ValidationError

- **WHEN** `validate_pattern` is called with a string that does not follow the pattern grammar
- **THEN** a `ValidationError` is raised rather than the base `StixError`

#### Scenario: Pattern message contains no parser internals

- **WHEN** an invalid pattern fails to parse
- **THEN** the message describes the syntax problem without Rust debug struct syntax such as `Error { input: …, code: … }`

### Requirement: Non-object JSON input produces a clear message

Parsing input that is valid JSON but not a JSON object SHALL produce an error message stating a STIX object was expected and what was received, without referencing internal type names.

#### Scenario: Array input rejected clearly

- **WHEN** `from_json` is called with a JSON array
- **THEN** the message states a JSON object was expected and identifies the array input

### Requirement: CustomObject rejects duplicate property specification

Constructing a `CustomObject` with the same property supplied both as a named argument and inside `custom_properties` SHALL raise a validation error naming the conflicting property, regardless of argument order. Supplying different properties through the two channels SHALL succeed.

#### Scenario: Conflicting property raises

- **WHEN** a CustomObject is constructed with `name` as a named argument and `name` also present in `custom_properties`
- **THEN** a validation error is raised naming `name`

#### Scenario: Conflict is order-independent

- **WHEN** the conflicting property is supplied in either argument order
- **THEN** the validation error is raised in both cases

#### Scenario: Distinct properties via both channels succeed

- **WHEN** a CustomObject is constructed with `name` as a named argument and a different property in `custom_properties`
- **THEN** construction succeeds and both properties appear in the serialized output

### Requirement: Messages never expose internal Rust paths

User-facing error messages SHALL NOT contain internal Rust module or type paths (such as `crate::` paths); they SHALL identify the failing construct by its user-facing name.

#### Scenario: Vocabulary constructor error names the class

- **WHEN** a Python vocabulary class is constructed with a value outside its vocabulary
- **THEN** the message names the vocabulary class (e.g. `ThreatActorType`) without any `crate::` or module path
- **AND** the message still lists the valid values
