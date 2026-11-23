# Tasks

## 1. Generic custom-object validation

- [ ] 1.1 Replace the hard `CustomMissingExtension` error in `CustomObject` with a `CustomObjectKind` (`Sdo`, `Sco`, `Sro`, `Generic`); validate generic objects with the §11.2 type-name, identifier, common-property, and custom-property rules, and emit `custom_missing_extension` as a warning. Verify unit tests cover an extension-less valid object, an extension-declared object with no warning, and an extension-less object with invalid type/property names.
- [ ] 1.2 Move `custom_missing_extension` from `KNOWN_ERROR_KINDS` to `KNOWN_WARNING_KINDS`, update the warning catalog tests and `docs/guides/errors.md`, and verify the documented catalog lists it as a warning.

## 2. Validation options and relationship policy

- [ ] 2.1 Add `RelationshipPolicy` (`Strict`, `AllowCustom`) to `CheckContext` and a `ValidationOptions` struct with `allow_custom`, `strict`, and `relationship_policy`; add `*_with_options` entry points for objects, bundles, and the envelope while keeping existing signatures strict by default. Verify unit tests show the default and explicit-strict paths behave identically.
- [ ] 2.2 Thread the policy through `Bundle::from_json_outcome_with_options` and `StixObject::from_value_outcome_with_options`; verify an options-based bundle test validates a valid fixture and preserves the existing outcome shape.

## 3. Lenient relationship checks

- [ ] 3.1 In `Relationship::check`, keep the current endpoint and pair checks under `Strict`; under `AllowCustom`, emit `custom_object_relationship_endpoint` and `relationship_pair_not_suggested` warnings instead of errors. Add both kinds to `KNOWN_WARNING_KINDS` and verify unit tests for a custom-object endpoint and a `tool uses attack-pattern` pair in both modes.
- [ ] 3.2 Document the two relaxation warnings in `docs/guides/errors.md` and `docs/guides/validation.md`, and verify the docs build succeeds.

## 4. CLI flag

- [ ] 4.1 Add `--allow-custom-relationships` to the CLI, map it to `RelationshipPolicy::AllowCustom`, and keep it independent of `--allow-custom`. Verify `--help` lists the flag and an integration test shows strict rejection and lenient acceptance with warnings for the same fixture.
- [ ] 4.2 Update `docs/cli.md` with the flag, strict-default behavior, and an ATT&CK-style example; verify every documented command runs against `testdata/stix/valid/bundle.json` or a committed fixture with the documented exit code.

## 5. Python binding

- [ ] 5.1 Add `allow_custom_relationships=False` to `Bundle.from_json` and `CustomObject.from_json`, forwarding to the options-based engine path. Verify a Python test shows strict rejection and lenient acceptance with warnings, and that existing calls without the keyword are unchanged.
- [ ] 5.2 Update the Python API reference and `docs/guides/validation.md` for the new keyword, and verify `uv run pyrefly check` and `uv run pytest` pass.

## 6. Regression fixtures

- [ ] 6.1 Add small fixtures for an extension-less custom object, a custom-object-to-Attack-Pattern relationship, and a `tool uses attack-pattern` relationship; verify the Rust matrix or dedicated tests cover strict and lenient outcomes.
- [ ] 6.2 Add a fixture-driven test that runs the CLI over the new fixtures with and without `--allow-custom-relationships`, asserting exit codes and warning kinds.

## 7. Integration verification

- [ ] 7.1 Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`; verify all pass.
- [ ] 7.2 Re-run MITRE ATT&CK `enterprise-attack.json` with `--allow-custom --allow-custom-relationships`; verify it reports a valid document with zero errors, record wall-clock time, peak memory, and warning counts in `review-notes.md`, and confirm the strict command still reports the relationship errors.
- [ ] 7.3 Run `uv run ruff check .`, `uv run pyrefly check`, and `uv run pytest`; verify all pass.

## Workflow follow-up

- Archive the change after review and after the parent `add-validation-cli` change is archived.
- Run the CLI against ATT&CK in the release workflow or a scheduled job if a long-term regression signal is wanted.
