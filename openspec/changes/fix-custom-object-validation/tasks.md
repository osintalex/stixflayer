# Tasks

## 1. Generic custom-object validation

- [x] 1.1 Replace the hard `CustomMissingExtension` error in `CustomObject` with a `CustomObjectKind` (`Sdo`, `Sco`, `Sro`, `Generic`); validate generic objects with the §11.2 type-name, identifier, common-property, and custom-property rules, and emit `custom_missing_extension` as a warning. Verify unit tests cover an extension-less valid object, an extension-declared object with no warning, and an extension-less object with invalid type/property names.
- [x] 1.2 Move `custom_missing_extension` from `KNOWN_ERROR_KINDS` to `KNOWN_WARNING_KINDS`, update the warning catalog tests and `docs/guides/errors.md`, and verify the documented catalog lists it as a warning.

## 2. Python generic custom objects

- [x] 2.1 Add `CustomObjectBuilder::from_generic` and use it from `from_parsed` when no new-object extension exists; expose `CustomObject.from_json` warnings for generic objects. Verify a Python test shows an extension-less custom object validates with `custom_missing_extension` and that an extension-declared object does not warn.

## 3. Strict relationship regression coverage

- [x] 3.1 Add small fixtures for an extension-less custom object, a custom-object-to-Attack-Pattern relationship, and a `tool uses attack-pattern` relationship; verify Rust and CLI tests show the custom object is valid with a warning while both relationship shapes remain invalid.
- [x] 3.2 Update `docs/guides/validation.md` and `docs/cli.md` to state that relationship validation is strict and there is no leniency flag; verify the docs build succeeds.

## 4. Integration verification

- [x] 4.1 Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`; verify all pass.
- [x] 4.2 Re-run MITRE ATT&CK `enterprise-attack.json` with strict validation; verify extension-less custom objects produce `custom_missing_extension` warnings while the relationship shapes produce errors, and record the counts in `review-notes.md`.
- [x] 4.3 Run `uv run ruff check .`, `uv run pyrefly check`, and `uv run pytest`; verify all pass.

## Workflow follow-up

- Archive the change after review and after the parent `add-validation-cli` change is archived.
