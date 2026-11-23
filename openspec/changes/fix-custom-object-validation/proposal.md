# Proposal

## Why

Validating MITRE ATT&CK's `enterprise-attack.json` exposed two spec-conformance problems. First, the engine rejects every custom object that lacks an `extension-definition` with a MUST-level `custom_missing_extension` error, but STIX 2.1 §11.2 says custom objects **SHOULD** be defined with the extension mechanism, not MUST; the section's own example has no `extensions` property. Second, feeds such as ATT&CK use custom object types as relationship endpoints and use spec-defined relationship names outside their defined source/target pairs, which strict §5.1 validation rejects. The first is a validator bug; the second needs an explicit, documented leniency mode rather than silently weakening validation for everyone.

## What Changes

- **Extension-less custom objects validate as generic custom objects.** A missing `new-sdo` / `new-sco` / `new-sro` extension becomes a SHOULD-level warning (`custom_missing_extension`) instead of a MUST-level error. Generic custom objects still enforce the §11.2 type-name, identifier, and custom-property rules.
- **Relationship validation stays strict by default.** Relationships still require SDO or SCO endpoints and still enforce the spec-defined source/target pairs.
- **New opt-in relationship leniency.** A new validation option accepts custom object types as relationship endpoints and accepts non-spec-defined source/target pairs for spec-defined relationship names. It is off by default and produces warnings for the relaxed checks so callers can see what was accepted.
- **CLI exposure.** `stixflayer` gains an explicit flag for the leniency mode; without it, ATT&CK-style bundles remain invalid.
- **Regression fixtures.** Small, hand-written fixtures reproduce the ATT&CK shapes: extension-less custom objects, relationships from custom objects to SDOs, and `tool uses attack-pattern`. The 52 MB ATT&CK file is not committed.
- **Documentation.** The CLI reference and validation guide explain strict vs lenient behavior and when to use each.

## Capabilities

### New Capabilities

- `custom-object-validation`: how extension-less custom objects are validated, how custom-object relationship endpoints are treated, and how strict-by-default versus opt-in leniency is exposed.

### Modified Capabilities

- `spec-conformance`: the custom-object extension requirement moves from a MUST-level error to a SHOULD-level warning, matching STIX 2.1 §11.2.

## Impact

- **Engine**: `rust/src/custom_objects/object.rs` (generic custom-object validation and warning), `rust/src/relationship_objects/relationship.rs` and `types.rs` (policy-aware endpoint/pair checks), `rust/src/validation.rs` and `rust/src/object.rs` (new validation options), `rust/src/error/mod.rs` (warning/error catalog if needed).
- **Bindings**: Rust public API gains an options-based entry point; the Python binding exposes the leniency option on bundle/object validation without changing existing defaults.
- **CLI**: `rust/stixflayer-cli` gains the flag and maps it to the engine option; report shape is unchanged.
- **Tests/fixtures**: new `testdata/stix/` fixtures and Rust/Python regression tests; ATT&CK itself is downloaded only for manual verification.
- **Docs**: `docs/cli.md`, `docs/guides/validation.md`, and the spec-conformance/error catalog documentation.
