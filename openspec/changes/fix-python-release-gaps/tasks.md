# Tasks

## 1. CustomObject conflict rule

- [x] 1.1 In `rust/src/python_bindings/meta.rs`, change the `custom_properties` branch to merge into the accumulated map and raise a validation error naming the property when a key arrives from both channels (order-independent, including equal values); verify with `cargo test` after adding the Rust test
- [x] 1.2 Update `src/stixflayer/stixflayer.pyi` CustomObject docstring/comment to state that named arguments and `custom_properties` write the same object properties and a property may be set exactly once; verify the stub still passes `uv run pyrefly check`
- [x] 1.3 Add Python regression tests in `tests/test_all_objects_ergonomics.py`: conflict raises regardless of argument order, error names the property, distinct properties via both channels serialize both; verify with `uv run pytest tests/test_all_objects_ergonomics.py`

## 2. Structured vocabulary variant

- [x] 2.1 In `rust/src/common/validation.rs`, replace the formatted `ValidationError(String)` for vocab failures with a new `InvalidVocabValue { value, vocabulary }` variant (display keeps a single `STIX validation error:` prefix); verify `cargo test` on vocab-related tests passes
- [x] 2.2 Add a Rust unit test asserting the new variant's `to_entry()` produces a rich entry with `value` and `vocabulary` fields; verify with `cargo test`

## 3. Total `.errors` contract

- [x] 3.1 In `rust/src/error/mod.rs`, add rich entries for `InvalidHash`, `ParseTimestampError`, `ParseIdentifierError`, `ParsePatternError`, and `InvalidVocabValue`; while there, clarify the `InvalidHash` message wording (the `unknown` hash-identity placeholder reads as noise — state plainly that the hash value's format doesn't match the declared hash type); verify existing envelope unit tests still pass with `cargo test`
- [x] 3.2 Add the catch-all entry (kind = variant name in snake_case, message = display) so every variant yields at least one entry; add a unit test asserting `errors()` is non-empty for every variant (enumerate them); verify with `cargo test`

## 4. Single-prefix nested messages

- [x] 4.1 Add the prefix-stripping nesting method to `StixError` and use it at the four composition sites (`rust/src/domain_objects/sdo.rs`, `rust/src/cyber_observable_objects/sco.rs`, `rust/src/relationship_objects/mod.rs` ×2); verify with `cargo test` that nested messages contain the prefix at most once
- [x] 4.2 Add a Python regression test constructing an invalid-vocab ThreatActor and asserting the message contains `STIX validation error:` exactly once and `.errors` carries the vocab entry; verify with `uv run pytest tests/test_validation.py`

## 5. Pattern error humanizing and category

- [x] 5.1 In `rust/src/pattern/mod.rs`, replace `e.to_string()` at the `map_err` with a describer mapping nom `ErrorKind`s to plain language including the remaining input; verify `cargo test` pattern tests pass and a bad-pattern message contains no `Error { … }` debug text
- [x] 5.2 Move `ParsePatternError` to the `"validation"` envelope category in `rust/src/error/mod.rs`; verify `validate_pattern` raises `ValidationError` in a Python test in `tests/test_validation.py`

## 6. Non-object JSON classification

- [x] 6.1 In `rust/src/python_bindings/convert.rs`, handle top-level non-object JSON before the existing bail so the message states a JSON object was expected and names the received kind (array/number/string/boolean/null) with no Rust type names; verify with a Rust unit test and a Python test feeding `from_json("[1,2,3]")`

## 7. Public surface cleanup

- [x] 7.1 Correct `validate_custom_property_name`'s doc comment in `rust/src/custom_property.rs` to state digits are allowed (remove the "must not start with a digit" claim); verify `cargo test` still passes (behavior unchanged)
- [x] 7.2 Delete `create_timestamp` from `rust/src/python_bindings/functions.rs`, its `m.add_function` registration and its `pub use` entry in `rust/src/python_bindings/mod.rs` (keeping `parse_extension_type`, which is internal-only), and its declaration in `src/stixflayer/stixflayer.pyi`; verify `python -c "import stixflayer; assert not hasattr(stixflayer, 'create_timestamp')"` and `uv run pyrefly check` pass

## 8. Release gate

- [x] 8.1 Create `release-gate/README.md` (run instructions, pass criteria) and `release-gate/01_pro_workflows.py` covering the professional scenario: SDO/SCO/SRO creation, serialize/roundtrip, bundle build/parse/add, ExtensionDefinition enrichment with markings and LanguageContent, CustomObject via both channels (including conflict-raise checks), allow_custom and non-strict modes, vocab enums; verify it runs green with `PYTHONPATH=src python release-gate/01_pro_workflows.py`
- [x] 8.2 Create `release-gate/02_error_audit.py` asserting the fixed behaviors: every audited failure raises the expected exception type with non-empty structured `.errors`, single-prefix nested messages, humanized pattern errors, clear non-object message, CustomObject conflict errors; verify it runs green with `PYTHONPATH=src python release-gate/02_error_audit.py`
- [x] 8.3 Create `release-gate/03_speed_sanity.py` timing parse/serialize of the benchmark bundles against the README's stated numbers with a generous threshold; verify it runs green with `PYTHONPATH=src python release-gate/03_speed_sanity.py`
- [x] 8.4 Create `release-gate/04_readme_examples.py` running every README example verbatim; verify it runs green with `PYTHONPATH=src python release-gate/04_readme_examples.py`

## 9. Final verification

- [x] 9.1 Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test`; all clean and green
- [x] 9.2 Run `uv run ruff check .`, `uv run pyrefly check`, and `uv run pytest`; all clean and green
- [x] 9.3 Run all four `release-gate/` scripts end-to-end and record results; keep the directory untracked for deletion before publishing
  - Results (2026-10-10): 01_pro_workflows 10/10 checks passed; 02_error_audit 9/9 checks passed; 03_speed_sanity passed (threshold = 100x README numbers); 04_readme_examples 5/5 examples ran verbatim. Directory left untracked.

## Workflow follow-up

- Delete `release-gate/` immediately before publishing (it is throwaway and never committed).
- Archive the change after review, so the `error-reporting` spec becomes part of the main specs.
