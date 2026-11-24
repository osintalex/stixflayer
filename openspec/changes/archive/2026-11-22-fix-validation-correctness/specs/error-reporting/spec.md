# Spec Delta

## ADDED Requirements

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
