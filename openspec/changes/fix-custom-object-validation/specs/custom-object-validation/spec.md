# Spec Delta

## Purpose

Defines how custom STIX object types participate in relationship validation and how callers opt in to accepting community feeds whose relationship endpoints or source/target pairs do not fit the strict STIX 2.1 relationship tables.

## ADDED Requirements

### Requirement: Custom-object relationship endpoints are rejected by default

By default, a Relationship SHALL require its `source_ref` and `target_ref` to identify SDOs or SCOs. A custom object type SHALL count as an SDO or SCO only when its `extensions` property declares a `new-sdo` or `new-sco` extension. A custom object without such a declaration MUST NOT be accepted as a relationship endpoint in strict mode.

#### Scenario: Extension-less custom object endpoint is invalid

- **WHEN** a Relationship points from an extension-less custom object to an Attack Pattern
- **THEN** validation fails with an error explaining that relationship endpoints must be SDOs or SCOs

#### Scenario: Declared custom SDO endpoint is valid

- **WHEN** a custom object declares a `new-sdo` extension and is used as a Relationship source
- **THEN** the endpoint is accepted in strict mode

### Requirement: Non-spec-defined relationship pairs are rejected by default

By default, a spec-defined relationship type SHALL only be accepted between the source and target object types the STIX 2.1 relationship tables define for it. Undefined pairs MUST use `related-to` or a user-defined relationship name.

#### Scenario: Undefined pair is invalid

- **WHEN** a `uses` Relationship points from a Tool to an Attack Pattern
- **THEN** validation fails because the specification's Attack Pattern table does not define that pair

#### Scenario: Defined pair is valid

- **WHEN** a `uses` Relationship points from an Attack Pattern to a Tool
- **THEN** the Relationship validates

### Requirement: Relationship leniency is opt-in

A validation option SHALL enable lenient relationship handling. When enabled, custom object types SHALL be accepted as relationship endpoints and spec-defined relationship names SHALL be accepted for source/target pairs the specification does not define. When disabled, the strict behavior above SHALL apply. The default SHALL be disabled.

#### Scenario: Leniency accepts a custom-object endpoint

- **WHEN** leniency is enabled and a Relationship points from an extension-less custom object to an Attack Pattern
- **THEN** the Relationship is accepted with a warning that the endpoint is a custom object

#### Scenario: Leniency accepts an undefined pair

- **WHEN** leniency is enabled and a `uses` Relationship points from a Tool to an Attack Pattern
- **THEN** the Relationship is accepted with a warning that the pair is not defined by the specification

#### Scenario: Default behavior is unchanged

- **WHEN** a caller does not enable leniency
- **THEN** custom-object endpoints and undefined pairs are rejected exactly as in strict mode

### Requirement: Lenient findings remain visible

Findings produced only because leniency was enabled SHALL be reported as warnings, not errors, and SHALL identify the relaxed check. The validation report shape MUST NOT change.

#### Scenario: Lenient endpoint warning

- **WHEN** leniency accepts a custom-object relationship endpoint
- **THEN** the outcome contains a warning whose kind identifies the custom-object endpoint relaxation

#### Scenario: Lenient pair warning

- **WHEN** leniency accepts a non-spec-defined relationship pair
- **THEN** the outcome contains a warning whose kind identifies the relationship-pair relaxation
