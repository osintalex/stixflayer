# Tasks

## 1. Indicator name is optional

- [x] 1.1 Delete the hand-written `name` check in `rust/src/domain_objects/sdo/indicator.rs` (the block commented `// name is required for Indicator`) and verify `cargo test -p stixflayer` passes with the struct's `Option<String>` unchanged.
- [x] 1.2 Move `testdata/stix/invalid/sdo/indicator-no-name.json` to `testdata/stix/valid/sdo/indicator-no-name.json`, remove the `indicator-name-required` rule from `testdata/test_matrix.json`, and remove the now-redundant `indicator-no-name-non-strict` rule; verify `uv run pytest tests -k matrix` passes.
- [x] 1.3 Add a bundle fixture with two Amnesty-shaped Indicators (no `name`, `pattern`, `pattern_type`, `valid_from`, `indicator_types`) under `testdata/stix/valid/sdos/` and a matching valid matrix entry; verify the matrix test parses it with zero errors.

## 2. Malware name is conditionally required

- [x] 2.1 Change the `DomainObjectType::Malware` arm of `check_required_fields` in `rust/src/domain_objects/sdo.rs` to require `name` only when `is_family` is true, and remove the discarded `stix_check()` calls from the `Location` and `Malware` arms; verify `cargo test -p stixflayer` passes.
- [x] 2.2 Add `testdata/stix/valid/sdos/malware-instance-no-name.json` (`is_family: false`, no `name`) and `testdata/stix/invalid/sdo/malware-family-no-name.json` (`is_family: true`, no `name`) with matrix rules asserting success and `missing_property` respectively; verify `uv run pytest tests -k matrix` passes.

## 3. Missing-field findings name only absent fields

- [x] 3.1 Replace the all-or-nothing Indicator arm in `check_required_fields` with a per-field check that reports only absent or empty required properties; verify a new unit test in `sdo.rs` produces one `missing_property` for `valid_from` when `pattern` and `pattern_type` are present.
- [x] 3.2 Add `testdata/stix/invalid/sdo/indicator-no-valid-from.json` and a matrix rule expecting exactly one `missing_property` naming `valid_from`; verify `uv run pytest tests -k matrix` passes and the error list contains no `pattern` finding.

## 4. Identifier UUID versions follow MUST/SHOULD

- [x] 4.1 Add the warning kind `identifier_uuid_not_v4` to `KNOWN_WARNING_KINDS` in `rust/src/error/mod.rs`, change `Identifier::check` in `rust/src/identifier.rs` to emit `ctx.warn(...)` for non-SCO UUIDv5 identifiers, and correct the message to say UUIDv4 is recommended (SHOULD); verify the `KNOWN_WARNING_KINDS` drift test passes and a unit test asserts `Ok(())` plus one warning.
- [x] 4.2 Keep unsupported versions (v1, v3) as `invalid_uuid` errors and verify with a unit test that a UUIDv1 identifier still returns `Err`.
- [x] 4.3 Add `testdata/stix/valid/sros/relationship-uuidv5.json` (valid, one expected warning) and `testdata/stix/invalid/sro/relationship-uuidv1.json` with matrix rules; verify `uv run pytest tests -k matrix` passes.
- [x] 4.4 Document `identifier_uuid_not_v4` in the warnings table in `docs/guides/errors.md` with its fields and spec basis (STIX 2.1 §2.9), and verify the row matches the kind string emitted by the test in 4.1.

## 5. Object-scoped findings carry the object id

- [x] 5.1 Add the `Located { object_id, error }` variant to `StixError` in `rust/src/error/mod.rs`, implement the `errors()` arm that stamps `Entry.object_id` when absent, and verify with a unit test that wrapping `MissingProperty` yields one entry with the expected `object_id` and an unchanged message.
- [x] 5.2 Extract `id` in `validate_value_from_object_parts` (`rust/src/validation.rs`) before the value is moved and wrap the returned error once, avoiding double wrapping; verify a unit test that a missing-property error for an object with an `id` carries that id.
- [x] 5.3 Stamp bundle-invariant findings in `rust/src/bundles/validation.rs`: duplicate-id entries use the duplicated id, relationship-reference entries use the relationship id; verify unit tests for both cases assert `object_id`.
- [x] 5.4 Add regression tests covering a bundle with a missing required property, a bundle with a wrong JSON type, and a direct single-object parse; verify each raised exception's `.errors[0]["object_id"]` equals the input id via `uv run pytest tests`.
- [x] 5.5 Add a test for unattributable input (object without `id`) asserting no `object_id` is invented, and verify the message still names the object type.

## 6. Integration verification

- [x] 6.1 Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` from `rust/`; verify all pass.
- [x] 6.2 Run `uv run ruff check .`, `uv run pyrefly check`, and `uv run pytest`; verify all pass.
- [x] 6.3 Manually validate the two public feeds (do not vendor them): `curl -sSL https://raw.githubusercontent.com/AmnestyTech/investigations/master/2023-03-29_android_campaign/malware.stix2` and `curl -sSL https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/cellebrite/cellebrite.stix2`, parse both with `Bundle.from_json_outcome`, and verify Amnesty reports zero errors and MVT reports zero errors with exactly one identifier warning; record the commands and counts in the change's review notes.

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- Verify the archived spec reflects the new `spec-conformance` capability and the updated `error-reporting` requirements.
