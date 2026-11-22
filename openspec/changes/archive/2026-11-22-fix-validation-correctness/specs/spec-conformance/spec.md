# Spec Delta

## Purpose

Guarantees that stixflayer enforces exactly the requiredness the STIX 2.1 property tables define — no optional property invented as required, no conditional requirement applied unconditionally — so documents published by the community validate the same way they do in the reference implementations.

## ADDED Requirements

### Requirement: Optional properties are not enforced as required

A property the STIX 2.1 specification marks optional SHALL be accepted when absent, for every object type. Validation MUST NOT reject a document solely because an optional property is missing.

#### Scenario: Indicator without a name is valid

- **WHEN** an Indicator omits `name` but provides `pattern`, `pattern_type`, and `valid_from`
- **THEN** the object validates successfully with no errors

#### Scenario: Malware instance without a name is valid

- **WHEN** a Malware object with `is_family` set to `false` omits `name`
- **THEN** the object validates successfully with no errors

#### Scenario: Amnesty-style indicator feed is accepted

- **WHEN** a bundle of Indicators that omit `name` (the shape published in Amnesty International's IOC feeds) is parsed
- **THEN** the bundle validates with no `missing_property` errors

### Requirement: Conditional required properties are enforced only when the condition holds

A property the specification requires only under a stated condition SHALL be enforced when that condition holds and MUST NOT be enforced otherwise.

#### Scenario: Malware family without a name is rejected

- **WHEN** a Malware object with `is_family` set to `true` omits `name`
- **THEN** validation fails with a `missing_property` error naming `name`

#### Scenario: Malware family with a name is accepted

- **WHEN** a Malware object with `is_family` set to `true` provides a non-empty `name`
- **THEN** the object validates successfully with no errors

### Requirement: Missing-property findings name only the absent fields

When a required property is missing, validation SHALL report a `missing_property` finding for each absent property and MUST NOT report a finding for a required property that is present.

#### Scenario: One absent required field produces one finding

- **WHEN** an Indicator provides `pattern` and `pattern_type` but omits `valid_from`
- **THEN** exactly one `missing_property` finding is produced, naming `valid_from`

#### Scenario: Several absent required fields produce one finding each

- **WHEN** an Indicator omits both `pattern` and `valid_from` while providing `pattern_type`
- **THEN** two `missing_property` findings are produced, naming `pattern` and `valid_from`, and none names `pattern_type`
