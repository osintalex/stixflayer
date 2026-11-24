# validation-outcomes Specification

## Purpose
Defines the language-agnostic result contract the engine returns to every binding: a structured outcome carrying pass/fail state, the validated value, MUST-level errors, and SHOULD-level warnings, with one stable entry shape and spec-based classification.

## Requirements

### Requirement: Validation returns a structured outcome

The engine SHALL represent every validation result as an outcome containing a `valid` flag, an optional validated value, a list of errors, and a list of warnings. A result with no errors SHALL be valid and SHALL carry the value; a result with errors SHALL be invalid and MUST NOT carry a value.

#### Scenario: Valid result with no findings

- **WHEN** a valid object with no SHOULD findings is validated
- **THEN** the outcome is valid, carries the object, and has empty errors and warnings

#### Scenario: Valid result with a SHOULD finding

- **WHEN** a valid object with a SHOULD finding is validated
- **THEN** the outcome is valid, carries the object, has empty errors, and has a non-empty warnings list

#### Scenario: Invalid result

- **WHEN** an object violates a MUST requirement
- **THEN** the outcome is invalid, carries no value, and has a non-empty errors list

### Requirement: Errors and warnings share one entry shape

Every entry SHALL contain a `kind` and a `message`, and MAY contain `property`, `value`, `vocabulary`, and `object_id`. Errors and warnings SHALL use the same shape. Entries MUST NOT contain a level or severity field; the containing list distinguishes MUST from SHOULD.

#### Scenario: Error entry shape

- **WHEN** a required property is absent
- **THEN** the error entry contains `kind`, `message`, and `property`

#### Scenario: Warning entry shape

- **WHEN** a hash uses an algorithm other than SHA-256
- **THEN** the warning entry contains `kind`, `message`, `property`, `value`, and `object_id`

#### Scenario: No level field

- **WHEN** any error or warning entry is inspected
- **THEN** it contains no `level` or `severity` field

### Requirement: MUST violations are errors and SHOULD violations are warnings

A value that violates a STIX 2.1 MUST requirement SHALL be reported as an error. A value that violates only a SHOULD requirement SHALL be reported as a warning and MUST NOT cause validation to fail.

#### Scenario: Closed enumeration value is an error

- **WHEN** an object is constructed with a value outside a closed enumeration
- **THEN** validation fails with an error entry

#### Scenario: Open-vocabulary value is a warning

- **WHEN** an object is constructed with an open-vocabulary value that is not in the suggested vocabulary
- **THEN** validation succeeds and the finding appears in warnings

#### Scenario: Non-SHA-256 hash is a warning

- **WHEN** an object is constructed with a valid hash whose algorithm is not SHA-256
- **THEN** validation succeeds and the finding appears in warnings

#### Scenario: Hash algorithm key is an error

- **WHEN** a hash key is neither in `hash-algorithm-ov` nor prefixed with `x_`
- **THEN** validation fails with an error entry

#### Scenario: Non-strict mode skips semantic checks

- **WHEN** an object is validated with semantic checks disabled
- **THEN** no semantic errors or warnings are produced

### Requirement: Warnings never fail validation

A validation result containing warnings and no errors SHALL be successful and SHALL return the validated value.

#### Scenario: Warning-bearing object is returned

- **WHEN** an object has one or more SHOULD findings and no MUST violations
- **THEN** the object is returned and the findings are available as warnings

### Requirement: Warning entries identify their object

A warning entry SHALL include the `object_id` of the STIX object it applies to when that object has an identifier.

#### Scenario: Bundle warning carries object id

- **WHEN** a bundle containing an object with a SHOULD finding is validated
- **THEN** the warning entry includes that object's `object_id`

### Requirement: Each object is semantically validated once

Each object SHALL be semantically validated at most once per entry-point call, and duplicate warnings MUST NOT appear in the outcome.

#### Scenario: Constructor emits one warning

- **WHEN** an object with one SHOULD finding is constructed
- **THEN** the result contains exactly one warning for that finding

#### Scenario: Bundle emits one warning per object

- **WHEN** a bundle contains one object with one SHOULD finding
- **THEN** the bundle outcome contains exactly one warning for that object

### Requirement: Warning state is scoped to one validation call

Warning collection SHALL be scoped to the validation call that produced it and MUST NOT leak into a later validation.

#### Scenario: No warning leakage between calls

- **WHEN** a warning-bearing object is validated and then a clean object is validated
- **THEN** the clean object's outcome has no warnings

### Requirement: Warning kinds are stable identifiers

Every warning SHALL carry a stable snake_case `kind`. Adding a kind is additive; renaming or removing a kind is a breaking change.

#### Scenario: Warning kind is snake_case

- **WHEN** a warning entry is inspected
- **THEN** its `kind` is a non-empty snake_case string

### Requirement: Case-preserved dictionaries are not warned for uppercase

The engine SHALL NOT report a lowercase recommendation for dictionary keys whose property requires or recommends case preservation.

#### Scenario: EXIF tag is not warned

- **WHEN** a file contains an EXIF tag key such as `XResolution`
- **THEN** no dictionary-key case warning is produced

#### Scenario: IPFIX key is not warned

- **WHEN** network traffic contains an IPFIX key such as `octetDeltaCount`
- **THEN** no dictionary-key case warning is produced

#### Scenario: Extension key is still warned

- **WHEN** an extensions dictionary contains an uppercase key where lowercase is recommended
- **THEN** a dictionary-key case warning is produced

### Requirement: Language tags accept any well-formed RFC 5646 value

Values for the common `lang` property and for `Software.languages` SHALL be accepted when they are well-formed RFC 5646 language tags, including ISO 639-2 three-letter codes, and rejected when malformed.

#### Scenario: ISO 639-2 code is accepted

- **WHEN** `lang` or `Software.languages` is set to `eng`
- **THEN** validation succeeds

#### Scenario: Region subtag is accepted

- **WHEN** `lang` is set to `en-US`
- **THEN** validation succeeds

#### Scenario: Malformed tag is rejected

- **WHEN** `lang` is set to a string that is not a well-formed RFC 5646 tag
- **THEN** validation fails with an error entry

### Requirement: HTTP request header names are not restricted to a fixed list

The `request_header` dictionary SHALL accept any valid HTTP header field name and MUST NOT reject a name solely because it is absent from a fixed list. Each header value SHALL be a list of strings, and a non-list value MUST be rejected.

#### Scenario: Custom header is accepted

- **WHEN** a network-traffic HTTP request extension contains a header named `X-Custom-Header` with a list value
- **THEN** validation succeeds

#### Scenario: Single and repeated header values are accepted

- **WHEN** `request_header` maps one header to `["value"]` and another to `["first", "second"]`
- **THEN** validation succeeds and both values survive serialization as lists

#### Scenario: String header value is rejected

- **WHEN** `request_header` maps a header to a bare string instead of a list
- **THEN** validation fails with a deserialization error

### Requirement: Dictionary keys allow up to 250 characters

Dictionary keys and hash keys SHALL be limited to 250 ASCII characters and MUST NOT be rejected at 30 characters.

#### Scenario: 31-character key is accepted

- **WHEN** a dictionary or hash key is 31 characters long and otherwise valid
- **THEN** validation succeeds

#### Scenario: 251-character key is rejected

- **WHEN** a dictionary or hash key is 251 characters long
- **THEN** validation fails with an error entry

### Requirement: Outcomes serialize to a language-agnostic JSON object

An outcome SHALL serialize to a JSON object containing `valid`, `errors`, and `warnings`, plus `value` when a value is present, so every binding consumes the same contract.

#### Scenario: Serialized outcome shape

- **WHEN** an outcome is serialized
- **THEN** the JSON object contains `valid`, `errors`, and `warnings`, and contains `value` only when validation succeeded
