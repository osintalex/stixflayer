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

A value outside a closed enumeration SHALL produce an `invalid_vocab_value` error entry that includes the rejected value and the vocabulary name. A value outside an open vocabulary's suggested values SHALL produce a warning entry instead and MUST NOT raise.

#### Scenario: Invalid vocabulary value includes context

- **WHEN** an object is constructed with a sophistication value not in the threat-actor sophistication vocabulary
- **THEN** construction succeeds and the `.warnings` entry includes the rejected value and the vocabulary name as structured fields

#### Scenario: Closed enumeration value raises

- **WHEN** an object is constructed with an opinion value outside the opinion enumeration
- **THEN** a `ValidationError` is raised and its `.errors` entry includes the rejected value and the vocabulary name

#### Scenario: Hash algorithm key remains an error

- **WHEN** a hash key is neither in `hash-algorithm-ov` nor prefixed with `x_`
- **THEN** a `ValidationError` is raised

### Requirement: Nested validation messages use a single prefix

When a validation failure message incorporates an inner failure's message, the combined message SHALL contain the `STIX validation error:` prefix at most once.

#### Scenario: Vocabulary failure inside an object-level failure

- **WHEN** an object fails validation because one of its vocabulary values is invalid
- **THEN** the exception message names the object and the underlying cause with the prefix appearing only once

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

### Requirement: Object-scoped findings carry the object identifier

Every error or warning that concerns a specific STIX object SHALL include that object's `id` in the entry's `object_id` field. This applies to findings produced before an object is fully constructed, such as missing required properties and JSON type mismatches.

#### Scenario: Structural failure names the object

- **WHEN** a bundle contains an Attack Pattern with an `id` but no `name`
- **THEN** the `missing_property` entry's `object_id` equals that Attack Pattern's `id`

#### Scenario: Type mismatch names the object

- **WHEN** a bundle contains an object whose `name` is a number rather than a string
- **THEN** the resulting `deserialization_error` entry's `object_id` equals that object's `id`

#### Scenario: Single-object parse names the object

- **WHEN** an object is parsed directly rather than as part of a bundle, and validation fails
- **THEN** the entry's `object_id` equals the `id` present in the input

#### Scenario: Bundle invariant names the object

- **WHEN** a bundle contains two objects with the same `id` and no differing `modified` timestamps
- **THEN** the duplicate-id entry's `object_id` equals the duplicated `id`

#### Scenario: Unattributable input does not invent an identifier

- **WHEN** the input has no `id`, or its `id` is not a string
- **THEN** the entry has no `object_id` and its message still identifies the object type

### Requirement: Non-SCO identifier UUID versions are SHOULD findings

STIX 2.1 states that SDO, SRO, Meta Object, and Bundle identifiers SHOULD use UUIDv4, not MUST. A non-SCO identifier using UUIDv5 SHALL produce a warning and MUST NOT reject the document. An identifier using a UUID version other than v4 or v5 SHALL remain an error.

#### Scenario: Relationship with a UUIDv5 identifier is accepted with a warning

- **WHEN** a Relationship uses a UUIDv5 identifier (the shape published in MVT's indicator collections)
- **THEN** the document validates and `.warnings` contains an entry whose kind identifies the identifier issue
- **AND** the message states that UUIDv4 is recommended rather than required

#### Scenario: Unsupported UUID version remains an error

- **WHEN** a non-SCO object identifier uses UUIDv1
- **THEN** validation fails with an `invalid_uuid` error

#### Scenario: SCO UUIDv5 identifiers are unaffected

- **WHEN** a cyber-observable object uses a spec-compliant UUIDv5 identifier
- **THEN** validation succeeds with no identifier warning

### Requirement: Exceptions carry warnings alongside errors

When validation produces both MUST errors and SHOULD findings, the raised exception SHALL expose the SHOULD findings in a `.warnings` list using the same entry shape as `.errors`.

#### Scenario: Exception exposes warnings

- **WHEN** an object violates a MUST rule and a SHOULD rule in the same validation
- **THEN** the raised exception's `.errors` is non-empty and `.warnings` contains the SHOULD finding

### Requirement: SHOULD violations never raise

Validation SHALL NOT raise for a SHOULD violation alone; it SHALL return the object with the finding available in `.warnings`.

#### Scenario: Open-vocabulary value does not raise

- **WHEN** an identity is constructed with an `identity_class` value not in `identity-class-ov`
- **THEN** construction succeeds and the finding appears in `.warnings`

#### Scenario: Non-SHA-256 hash does not raise

- **WHEN** a file is constructed with a valid MD5 hash
- **THEN** construction succeeds and the finding appears in `.warnings`
