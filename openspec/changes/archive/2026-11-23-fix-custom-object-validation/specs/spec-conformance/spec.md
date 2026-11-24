# Spec Delta

## ADDED Requirements

### Requirement: Extension-less custom objects are valid with a warning

A custom object that omits the `extensions` property SHALL validate successfully when it satisfies the STIX 2.1 custom-object type-name, identifier, common-property, and custom-property rules. The absence of a `new-sdo`, `new-sco`, or `new-sro` extension SHALL produce a SHOULD-level warning and MUST NOT produce a MUST-level error.

#### Scenario: Extension-less custom object validates

- **WHEN** a custom object has a valid `x-` type name, identifier, common properties, and custom properties but no `extensions` property
- **THEN** validation succeeds and reports a warning whose kind identifies the missing extension

#### Scenario: Custom object with a new-object extension does not warn

- **WHEN** a custom object declares a `new-sdo`, `new-sco`, or `new-sro` extension
- **THEN** validation succeeds without a missing-extension warning

#### Scenario: Extension-less custom object still enforces custom-object rules

- **WHEN** an extension-less custom object has an invalid type name, identifier, or custom-property name
- **THEN** validation fails with the corresponding error rather than being accepted because the extension is absent
