# Proposal

## Why

stixflayer currently rejects valid STIX 2.1 published by the community it is meant to serve. Running the engine against Amnesty International's public IOC feed (`malware.stix2`, 4,375 objects) produces **2,187 errors, every one of them a false positive**: `Indicator is missing required property 'name'`. MVT's `cellebrite.stix2` is rejected for the same reason plus a SHOULD-level identifier rule enforced as a MUST. Both files parse cleanly in `stix2`, and the OASIS specification says `name` is optional for Indicator.

Three hand-written rules have drifted from the specification, and one of them breaks the two most important public IOC feeds in the mobile-forensics ecosystem. The project's positioning — "faster and more correct" — cannot ship until the validator stops inventing MUSTs.

## What Changes

- **Indicator `name` becomes optional.** Remove the hand-written check in `rust/src/domain_objects/sdo/indicator.rs`. The struct already models `name: Option<String>`; the spec table says `name (optional)`.
- **Malware `name` becomes conditionally required.** The spec requires it only for a malware *family*: "For a malware family the name MUST be defined." Enforce it when `is_family == true` and accept it absent otherwise.
- **Non-SCO UUIDv5 identifiers become a warning, not an error.** STIX 2.1 §2.9 says SDO/SRO/Meta/Bundle identifiers **SHOULD** use UUIDv4, not MUST. Correct both the classification and the message, which currently misquotes the spec. This turns MVT's `relationship--de7d55fe-…` from a rejection into a SHOULD finding.
- **Stop over-reporting missing required fields.** `check_required_fields` currently returns `pattern`, `pattern_type`, *and* `valid_from` as missing whenever any one of them is absent. Report only the fields that are actually missing.
- **Attribute object-scoped findings to the object.** Add a `StixError::Located { object_id, error }` wrapper and stamp it at the single validation choke point (`validate_value_from_object_parts`), so structural failures — missing properties, wrong JSON types — carry `object_id` in their `Entry`. Bundle invariants stamp their own entries where the object is in hand.
- **Regression coverage from real-world shapes.** Add fixtures that reproduce the Amnesty and MVT object shapes (an Indicator without `name`, a Malware instance without `name`, a non-SCO UUIDv5 id) so these can never regress. Do not vendor the multi-megabyte upstream feeds; a documented manual check against the public URLs is enough.

No public Python or Rust API is removed. The error enum gains one additive variant; the `.errors` entry shape gains no fields.

## Capabilities

### New Capabilities

- `spec-conformance`: the validator applies STIX 2.1 requiredness exactly as the specification's property tables state it — optional properties are not invented as required, conditional requirements are conditional, and missing-field findings name only the fields that are actually absent.

### Modified Capabilities

- `error-reporting`: object-scoped failures now carry `object_id` in their structured entries, and identifier UUID-version findings are classified as SHOULD warnings rather than MUST errors.

## Impact

- **Rust code**: `domain_objects/sdo/indicator.rs`, `domain_objects/sdo.rs` (`check_required_fields`), `domain_objects/sdo/malware.rs`, `identifier.rs`, `validation.rs` (id extraction and wrapper), `error/mod.rs` (`Located` variant and `errors()` flattening), `bundles/validation.rs` (invariant attribution).
- **Fixtures/tests**: `testdata/stix/` gains Indicator-without-name, Malware-instance-without-name, and non-SCO-UUIDv5 cases; `testdata/test_matrix.json` gains the corresponding entries.
- **Docs**: the spec-conformance notes in `README.md` / `docs/` are updated by the `reposition-python-first` change, not here.
- **Downstream**: the `add-validation-cli` change consumes this behaviour; without it the CLI's first public run would report thousands of false positives against Amnesty's Pegasus feed.
- **Not changed**: no STIX 2.0 support, no pattern-grammar changes, no vocabulary changes.
