# Spec Delta

## MODIFIED Requirements

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

## ADDED Requirements

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
