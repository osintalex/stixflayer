# Spec Delta

## ADDED Requirements

### Requirement: Messages never expose internal Rust paths

User-facing error messages SHALL NOT contain internal Rust module or type paths (such as `crate::` paths); they SHALL identify the failing construct by its user-facing name.

#### Scenario: Vocabulary constructor error names the class

- **WHEN** a Python vocabulary class is constructed with a value outside its vocabulary
- **THEN** the message names the vocabulary class (e.g. `ThreatActorType`) without any `crate::` or module path
- **AND** the message still lists the valid values
