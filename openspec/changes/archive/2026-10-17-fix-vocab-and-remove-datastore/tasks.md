# Tasks

## 1. Vocabulary values (breaking)

- [x] 1.1 In `rust/src/cyber_observable_objects/vocab.rs`: correct serialized values — `Reg_DWORD` → `REG_DWORD`, `REG_RESOURCEL_REQUIREMENTS_LIST` → `REG_RESOURCE_REQUIREMENTS_LIST`, `Imcp` → `Icmp` (emits `icmp`); align variant names with emitted values
- [x] 1.2 In `rust/src/domain_objects/vocab.rs`: replace `EmergencyServicesSanitation` with `EmergencyServices` (emits `emergency-services`)
- [x] 1.3 In `rust/src/cyber_observable_objects/sco.rs`: correct `PROTOCOLS_MAP` entries `"imcp-ext"`/`"imcp"` → `"icmp-ext"`/`"icmp"`
- [x] 1.4 Update tests/fixtures referencing the old values; add assertions for the four corrected values

## 2. Vocabulary error messages

- [x] 2.1 In `rust/src/python_bindings/vocab.rs`: change the `make_vocab_enum!` error format from `stringify!($enum_type)` to `stringify!($name)`
- [x] 2.2 Add a test asserting the Python-facing message contains the clean class name and no `crate::` path, and still lists the valid values

## 3. Datastore removal (breaking)

- [x] 3.1 Delete `rust/src/datastore/` (`mod.rs`, `filesystem.rs`, `filters.rs`) and remove `pub mod datastore;` from `rust/src/lib.rs`
- [x] 3.2 Remove the six orphaned `StixError` variants (`MissingDataSource`, `MissingDataSink`, `UnsupportedDataType`, `PathNotFound`, `ObjectNotFound`, `IoError`) and their arms in the error envelope/category code and the Python exception mapping
- [x] 3.3 Remove or update tests that referenced the datastore or the removed error kinds
- [x] 3.4 Update `docs/guides/errors.md` (kind list) and sweep docs/README for any datastore references

## 4. pytest-examples upstream note

- [x] 4.1 Keep the pyrefly suppression in `tests/test_docs_examples.py`; file or link the upstream issue for the stale annotation (its `Literal` omits `py311`) and reference it from the suppression comment

## 5. Verification

- [x] 5.1 Run the full quality gate: `ruff check`, `pyrefly check`, `pytest`, `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --workspace`, and `cargo doc --workspace --no-deps` with `-D warnings`
- [x] 5.2 Verify the spec scenarios via tests: `REG_DWORD`, `REG_RESOURCE_REQUIREMENTS_LIST`, `icmp` in the protocol map, `emergency-services`, and the clean vocabulary error message
