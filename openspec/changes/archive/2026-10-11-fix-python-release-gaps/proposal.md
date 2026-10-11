# Proposal

## Why

Live acceptance probing of the public API before the first release found one data-loss bug and inconsistent error reporting. `CustomObject` construction can silently drop caller data depending on argument order — the worst possible failure mode for a validation library — and the structured `.errors` contract is unreliable (empty for most failure types), with several messages leaking Rust internals to Python users. Fixing now, while nothing is published, avoids any compatibility burden.

## What Changes

- **CustomObject property conflicts raise** — supplying the same property via a named argument and `custom_properties` raises instead of silently dropping one depending on argument order (`rust/src/python_bindings/meta.rs`).
- **`.errors` always populated** — every `stix` exception carries at least one structured entry; rich entries for variants with natural structure (hash, timestamp, identifier, pattern, vocab), generic catch-all for the rest.
- **Structured vocabulary errors** — new `InvalidVocabValue { value, vocabulary }` variant replacing the formatted string at the central vocab check, enabling rich entries and clean nesting.
- **Single-prefix nested messages** — the four "X is not a valid Y: …" composition sites stop duplicating the `STIX validation error:` prefix.
- **Humanized pattern errors** — pattern parse failures no longer leak nom's Debug form (`Error { input: …, code: Char }`); they also move from base `StixError` to `ValidationError` so callers get one catch type for invalid input. **(Behavior change, pre-release: no compatibility concern.)**
- **Clear non-object input message** — `from_json("[1,2,3]")` reports "expected a STIX object (JSON object), got array" instead of `expected struct DomainObject`.
- **Doc-comment fix** — `validate_custom_property_name` states the spec rule correctly (digits ARE allowed in custom property names).
- **Remove `create_timestamp`** — orphaned public helper with zero internal or test callers; its echo-on-error behavior (invalid input returned unchanged) was a footgun, and its normalization is redundant with constructor behavior. **(Pre-release: no compatibility concern.)**
- **Release gate** — new throwaway `release-gate/` directory of dependency-free Python scripts exercising professional workflows, the error audit, speed sanity, and README examples; run before publishing, then deleted. Recorded as a task, not a durable artifact.

Out of scope (parked, decided during exploration): warnings-as-data / SHOULD-violation surfacing (future outcome-with-warnings design), logging bridges (pyo3-log), pattern grammar completeness (existing backlog ticket), any change to the `x_` prefix enforcement (SHOULD stays unenforced by design).

## Capabilities

### New Capabilities

- `error-reporting`: How validation failures surface to Python callers — exception categories, the always-populated structured `.errors` contract, message quality (single-prefix nesting, no Rust-internals leaks), and the CustomObject property-conflict rule.

### Modified Capabilities

(none — `python-api`'s requirements about entry points and stub sync are unaffected)

## Impact

- **Code**: `rust/src/python_bindings/meta.rs` (conflict detection), `rust/src/error/mod.rs` (total `to_entry`, new variant), `rust/src/common/validation.rs` (structured vocab errors), `rust/src/pattern/mod.rs` (error humanizing + category), `rust/src/python_bindings/convert.rs` (non-object classification), `rust/src/python_bindings/functions.rs` and `rust/src/python_bindings/mod.rs` (`create_timestamp` removal), nesting sites in `rust/src/domain_objects/sdo.rs`, `rust/src/cyber_observable_objects/sco.rs`, `rust/src/relationship_objects/mod.rs`, `rust/src/custom_property.rs` (doc comment).
- **Public API**: `CustomObject` raises on property conflicts; `validate_pattern` raises `ValidationError` instead of `StixError`; `create_timestamp` is removed from the public surface; every exception instance has a non-empty `.errors` list. Nothing is published yet, so no compatibility concern.
- **Stubs**: `.pyi` updates if exception documentation changes (per the existing `python-api` stub-sync requirement).
- **Tests**: Rust unit tests for the error contract and conflict detection; Python regression tests; `release-gate/` scripts exercising the fixed behaviors.
