# Proposal

## Why

Validating MITRE ATT&CK's `enterprise-attack.json` exposed a validator bug: the engine rejects every custom object that lacks an `extension-definition` with a MUST-level `custom_missing_extension` error. STIX 2.1 §11.2 says custom objects **SHOULD** be defined with the extension mechanism, not MUST; the section's requirements do not require an `extensions` property and its own example has none. The relationship errors ATT&CK also triggers are a separate matter: §5.1 requires SDO/SCO endpoints and the relationship tables define the allowed source/target pairs, so strict validation should keep rejecting those shapes rather than adding a leniency mode.

## What Changes

- **Extension-less custom objects validate as generic custom objects.** A missing `new-sdo` / `new-sco` / `new-sro` extension becomes a SHOULD-level warning (`custom_missing_extension`) instead of a MUST-level error. Generic custom objects still enforce the §11.2 type-name, identifier, and custom-property rules.
- **BREAKING**: Remove the `StixError::CustomMissingExtension` error variant. The `custom_missing_extension` kind remains in the cross-language report, now as a warning. Rust callers that matched the variant must switch to the warning path.
- **Relationship validation stays strict.** There is no flag or option for accepting custom-object relationship endpoints or non-spec-defined pairs. ATT&CK's relationship errors are reported as errors.
- **Regression fixtures.** Small fixtures cover extension-less custom objects and the ATT&CK relationship shapes that must remain invalid. The 52 MB ATT&CK file is not committed.
- **Documentation.** The warning catalog and validation guide explain the generic-custom-object behavior and the strict relationship rules.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `spec-conformance`: the custom-object extension requirement moves from a MUST-level error to a SHOULD-level warning, matching STIX 2.1 §11.2.

## Impact

- **Engine**: `rust/src/custom_objects/object.rs` (generic custom-object validation and warning), `rust/src/custom_objects/builder.rs` (generic parsed-object builder), `rust/src/error/mod.rs` (warning catalog).
- **Python binding**: `CustomObject.from_json` supports generic custom objects and exposes their warnings.
- **Tests/fixtures**: new `testdata/stix/custom_objects/` fixtures and Rust/Python regression tests; ATT&CK itself is downloaded only for manual verification.
- **Docs**: `docs/guides/errors.md`, `docs/guides/validation.md`, and the CLI docs.
