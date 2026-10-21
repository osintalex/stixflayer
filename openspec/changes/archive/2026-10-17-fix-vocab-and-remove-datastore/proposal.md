# Proposal

## Why

Four defects surfaced during the documentation pass: vocabulary constructor errors leak internal Rust module paths to Python callers (`Invalid crate::domain_objects::vocab::ThreatActorType value: 'bogus'`), four serialized vocabulary values contradict the ST 2.1 specification and IANA registries (`Reg_DWORD`, `REG_RESOURCEL_REQUIREMENTS_LIST`, `imcp`, `emergency-services-sanitation`), the entire `datastore` module (614 lines, including a filter model nothing evaluates) is unreachable from any test, binding, or doc, and the pinned `pytest-examples` release carries a stale type annotation that forces a type-checker suppression in our test harness.

## What Changes

- **BREAKING** — Correct serialized vocabulary values to match the ST 2.1 specification and IANA: `Reg_DWORD` → `REG_DWORD`, `REG_RESOURCEL_REQUIREMENTS_LIST` → `REG_RESOURCE_REQUIREMENTS_LIST`, `imcp` → `icmp` (also in the network-traffic extension→protocol map), `emergency-services-sanitation` → `emergency-services`. No compatibility aliases: nobody has consumed the wrong values.
- Vocabulary constructor error messages stop exposing Rust paths: the Python vocabulary classes report the clean class name (`Invalid ThreatActorType value: 'bogus' …`) instead of `crate::domain_objects::vocab::ThreatActorType`.
- **BREAKING** — Remove the unused `datastore` module entirely (`DataStore`, `DataSink`, `DataSource`, `FilesystemStore`, filters) together with the six error variants only it used (`MissingDataSource`, `MissingDataSink`, `UnsupportedDataType`, `PathNotFound`, `ObjectNotFound`, `IoError`) and their Python exception mappings. Nothing outside the module references any of it.
- Record the `pytest-examples` 0.0.18 stale annotation (omits `py311`) as a known upstream issue; keep the justified suppression in the test harness.

## Capabilities

### New Capabilities

- `stix-vocabularies`: the library's serialized vocabulary values match the ST 2.1 specification and IANA registries exactly.

### Modified Capabilities

- `error-reporting`: user-facing failure messages SHALL NOT expose internal Rust module or type paths (extends the existing message-quality requirements to the vocabulary constructors).

## Impact

- Rust: `src/domain_objects/vocab.rs`, `src/cyber_observable_objects/vocab.rs`, `src/cyber_observable_objects/sco.rs` (protocol map), `src/python_bindings/vocab.rs`, `src/error/mod.rs` (variant removal), `src/python_bindings/error.rs` (mapping removal), deletion of `src/datastore/`.
- Python API: unchanged except narrower error surface (fewer error kinds) and corrected vocabulary values.
- Docs: `docs/guides/errors.md` error-kind list loses the datastore kinds; vocabulary pages show corrected values.
- Tooling: no dependency changes; suppression comment in `tests/test_docs_examples.py` stays.
