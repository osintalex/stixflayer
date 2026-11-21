# Tasks

## 1. Outcome types and validation context

- [x] 1.1 Add `Entry` and `Outcome<T>` in `rust/src/error/` (`Entry { kind, message, property?, value?, vocabulary?, object_id? }`; `Outcome { valid, value?, errors, warnings }`) with `Serialize` and `skip_serializing_if` on optionals; verify unit tests assert the JSON shape (`valid`, `errors`, `warnings`, optional `value`) and that no `level`/`severity`/`properties`/`expected`/`got` keys are emitted.
- [x] 1.2 Replace the existing `ErrorEntry`/`ErrorEnvelope` usage with the shared `Entry`/`Outcome` shape (keep a compatibility alias only if a Rust caller needs it); update `StixError::to_json` and its tests; verify `cargo test -p stixflayer error` passes.
- [x] 1.3 Add `CheckContext` with a warning vector, an optional current `object_id`, a `warn(...)` helper that stamps the id, and `into_warnings()`; verify unit tests for entry stamping and for no leakage between two contexts.
- [x] 1.4 Add `Outcome::from_result`, `Outcome::to_json`, and `valid = errors.is_empty()`; verify tests for valid-with-no-findings, valid-with-warnings, and invalid outcomes.

## 2. Thread the context through validation

- [x] 2.1 Change the `Stix` trait to `fn check(&self, ctx: &mut CheckContext) -> Result<(), StixError>` and provide `stix_check()` (discarding wrapper) and `outcome()`; verify `cargo build --workspace` and a representative `cargo test`.
- [x] 2.2 Migrate all `impl Stix` bodies and every `.stix_check()` call site to `check(ctx)` (use GritQL for the mechanical rename, then fix helper functions that need `ctx`); verify `cargo build --workspace` and `cargo test --workspace` compile and pass with no `.stix_check()` left in validation internals except the compatibility wrapper.
- [x] 2.3 Move the 14 production `warn!` sites to `ctx.warn(...)` with the catalog kinds, and delete the test-only `warn!`/`eprintln!` residue in `ipv4_addr`, `ipv6_addr`, `email_addr`, `tool`, `mac_addr`, and `artifact`; verify a Rust test per warning kind (hash, dictionary key, extension key, external reference, network-traffic port, protocol, relationship type, marking definition type, observed-data refs, open vocabulary, lowercase/hyphenated value).
- [x] 2.4 Add outcome-returning entry points (`validate_value_from_object_outcome`, `parse_sdo_outcome`, `parse_sco_outcome`, `parse_sro_outcome`, `StixObject::from_value_outcome`/`from_json_outcome`) and keep the existing `Result` APIs as warning-discarding wrappers; verify tests that the outcome variant carries warnings and the `Result` wrapper still behaves identically.
- [x] 2.5 Move the SHA-256 and dictionary-case warnings out of construction helpers (`check_hash_key`, `check_dictionary_key`) into `check`; verify constructing a warning-bearing object does not emit a warning until validation, and that one validation emits exactly one.

## 3. Collapse the redundant pass

- [x] 3.1 Move the SDO/SCO/SRO builder present-but-empty checks into `check` and unify `missing_builder_property` with `missing_property`; verify the empty-name parity test (`AttackPattern.from_json('{"name": ""}')` and `AttackPattern(name="")` both fail with the same kind/message) and builder tests pass.
- [x] 3.2 Make `build_no_validate` assembly-only, add `build_outcome()`, and keep `build()` as assembly + `check`; verify serialization tests (`to_json` does not re-check) and builder tests pass.
- [x] 3.3 Collapse the Python constructor path to `validate_value_outcome` → `from_parsed` → wrapper and delete `validate_sdo_builder`/`validate_sco_builder`/`validate_sro_builder`/`validate_marking_builder`; verify a constructor and `from_json` produce the same errors and warnings for the same input.
- [x] 3.4 Add dedupe keyed by `(object_id, kind, property, value)`; verify a warning fires exactly once in a constructor and once per object in a bundle.

## 4. Collapse the bundle pass

- [x] 4.1 Restructure `Bundle::from_json` to deserialize raw object values, validate each once through the outcome pipeline, aggregate warnings, and run bundle invariants only; keep `Bundle::stix_check` as the full check for programmatic bundles; verify valid, invalid, duplicate-id, and enforce-refs bundle tests.
- [x] 4.2 Add the bundle outcome path and pass per-object warnings into `wrap_stix_object`; verify `bundle.warnings` and `bundle.objects[i].warnings` both contain the finding with the correct `object_id`.
- [x] 4.3 Decide and implement `strict`/`allow_custom` on `Bundle.from_json` (currently ignored) or document them as unsupported; verify the chosen behavior with tests.

## 5. Reclassification and spec fixes

- [x] 5.1 Split vocabulary validation into closed-enum errors and open-vocabulary warnings, and audit every `validate_vocab_value`/`validate_vocab_list`/`is_vocab_value` call site; verify `identity_class="bogus-class"` warns, `opinion` outside its enum errors, and a hash key outside `hash-algorithm-ov` (without `x_`) errors.
- [x] 5.2 Reclassify dictionary case, kill-chain format, and malware-type format as warnings; scope `dictionary_key_not_lowercase` to `extensions` and exempt case-preserved dictionaries; verify EXIF (`XResolution`), IPFIX (`octetDeltaCount`), HTTP header, email header, PDF info, socket option, language-content, and environment-variable tests produce no warning, while an uppercase `extensions` key does.
- [x] 5.3 Replace the 30-character hash-key and observable-dictionary-key limits with 250; verify a 31-character key is accepted and a 251-character key is rejected.
- [x] 5.4 Normalize the SHA-256 comparison and report spec vocabulary names at custom-message sites; verify `sha-256` does not warn and `pattern-type-ov`/`malware-type-ov`/`account-type-ov` appear in the `vocabulary` field.
- [x] 5.5 Validate `CommonProperties.lang` and `Software.languages` as well-formed RFC 5646 tags (parse-only), delete `cyber_observable_objects/lang_codes.rs` and its exports, and update tests; verify `eng`, `en`, `en-US`, and `zh-Hant-TW` are accepted and malformed input is rejected.
- [x] 5.6 Remove the fixed HTTP request-header list; verify a custom header such as `X-Custom-Header` is accepted and no case warning is emitted.
- [x] 5.7 Implement the `observed_data_unrecognized_ref` and `observed_data_no_recognized_sco` unverifiable warnings; verify a custom ref warns and a known SDO ref errors.
- [x] 5.8 Update the docs catalog with errors and warnings tables (`kind`, array, basis, fields, meaning, spec), add a `KNOWN_ERROR_KINDS` const, and extend the `all_variants()` drift test; verify every reachable kind appears in the catalog and every catalog row has a test or fixture.

## 6. Python surface

- [x] 6.1 Add a second tuple field for warnings to every `#[pyclass]` wrapper and a `.warnings` getter returning a list of dicts; verify `obj.warnings` on each object class and that `strict=False` yields an empty list.
- [x] 6.2 Pass warnings through `stix_to_pyerr` so exceptions expose both `.errors` and `.warnings`; verify an input that violates a MUST and a SHOULD exposes both lists.
- [x] 6.3 Add the non-raising `check()` entry point and the Python `Outcome` class (`.valid`, `.errors`, `.warnings`, `.value`, `.to_json()`); verify valid-with-warnings and invalid cases return the right fields without raising.
- [x] 6.4 Update `src/stixflayer/stixflayer.pyi` and `__init__.pyi` with `.warnings`, `Outcome`, and `check`; verify `uv run pyrefly check` and the stub-sync test.
- [x] 6.5 Add Python tests for `.warnings`, exception warnings, `check()`, `strict=False`, bundle attribution, and dedupe; verify `uv run pytest --benchmark-disable` passes.

## 7. Documentation and cross-language contract

- [x] 7.1 Rewrite the README's conformance wording to be spec-first: remove the reference-validator framing from the existing "Known divergences" section and the "Battle-tested… parity against cti-stix-validator" bullet, keep the technical notes as spec-conformance notes, and document the spec rules users may care about (250-character keys, well-formed RFC 5646 language tags including ISO 639-2, unrestricted HTTP header names, SHOULD findings as warnings) without naming the validator; verify the README has no reference-validator mentions, the spec-conformance notes are present, and the README renders correctly.
- [x] 7.2 Update `docs/guides/validation.md` and `docs/guides/errors.md` with the `strict=True`/`strict=False` model, the shared entry shape, the errors + warnings catalog, `.warnings`, and `check()`; verify `uv run pytest tests/test_docs_examples.py` passes.
- [x] 7.3 Add `expected_warnings` and warning fixtures to `testdata/test_matrix.json`; verify the matrix tests assert the same kinds and no message substrings.
- [x] 7.4 Add benchmark coverage for the collapsed constructor/parse paths and record the before/after comparison in the change; verify `uv run pytest benchmarks --benchmark-only` runs and no regression exceeds the agreed threshold.

## 8. Release and full gate

- [x] 8.1 Bump `rust/Cargo.toml` and `pyproject.toml` to `0.1.1`, regenerate `uv.lock`, and decide/bump `rust/stixflayer_derive/Cargo.toml` (updating the main crate's dependency requirement if bumped); verify the release gate script reports a release for `0.1.1`.
- [x] 8.2 Run the full gate: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyrefly check`, and `uv run pytest --benchmark-disable`; verify all green.
- [x] 8.3 Run `openspec validate add-validation-outcomes --strict` and verify no errors.

## Workflow follow-up

- Archive the change after review requirements are satisfied.
- Verify the archived result and the release artifacts.
