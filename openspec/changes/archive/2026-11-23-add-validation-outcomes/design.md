# Design

## Context

See `proposal.md` — Why. Current constraints that shape the approach:

- `Stix::stix_check(&self) -> Result<(), Error>` has no channel for non-fatal findings. The 14 production `warn!` sites go through the `log` facade; no logger is installed in Python, so Python callers never see them. There is no `pyo3-log` bridge and this change does not add one.
- Validation already runs more than once in common paths: Python constructors call `validate_value` (which runs `stix_check`) and then `validate_sdo_builder` → `build()` (which runs `stix_check` again); `Bundle::from_json` validates each object during deserialization and again in `bundle.stix_check()`. This also causes a constructor/`from_json` divergence: `AttackPattern.from_json('{"name": ""}')` succeeds while `AttackPattern(name="")` fails, because `from_json` never runs the builder's present-but-empty checks.
- The existing `ErrorEntry` is sparse and already a cross-language contract: `kind`, `message`, optional `property`, `properties`, `expected`, `got`, `value`, `vocabulary`. `kind` is stable API surface; the catch-all derives kinds from variant names.
- Several rules inherited from `stix2validator` strict mode are stricter than STIX 2.1: 30-character dictionary/hash keys, a fixed language-code list that rejects ISO 639-2, a fixed HTTP request-header list, and treating open-vocabulary recommendations as errors.
- The `language_tags` crate's `LanguageTag::validate()` uses an incomplete IANA registry and rejects valid RFC 5646 tags such as `eng` and `aar`.

## Goals / Non-Goals

**Goals:**

- One language-agnostic result contract for every binding: `Outcome<T>` with `valid`, `value`, `errors`, and `warnings`.
- Explicit, compiler-enforced warning collection. No ambient sink, no global state, no cross-call leakage.
- Each object semantically validated exactly once per entry-point call.
- MUST violations fail; SHOULD violations warn and never fail.
- Remove the non-spec `stix2validator` strictness in the paths this change touches.
- Keep the Python API idiomatic: objects with `.warnings` and exceptions with `.errors` + `.warnings`.

**Non-Goals:**

- Implementing every SHOULD the spec defines. This change covers the SHOULDs the engine already checks plus the reclassified ones; extension-definition `description`/`url`/`extension_properties` and similar uncovered SHOULDs are a separate coverage audit.
- Registry-valid-only language tags. The contract is well-formed RFC 5646.
- `pyo3-log` or any logging bridge.
- Pattern grammar changes.
- New language bindings.

## Decisions

### D1: Outcome-first core, idiomatic bindings

The core computes `Outcome<T>` and bindings project it. Python maps success to the object with `.warnings` and failure to an exception with `.errors` and `.warnings`. This is the D8 direction recorded in `openspec/changes/archive/2026-10-11-fix-python-release-gaps/design.md`.

```rust
pub struct Outcome<T = ()> {
    pub valid: bool,
    pub value: Option<T>,
    pub errors: Vec<Entry>,
    pub warnings: Vec<Entry>,
}

pub struct Entry {
    pub kind: String,
    pub message: String,
    pub property: Option<String>,
    pub value: Option<String>,
    pub vocabulary: Option<String>,
    pub object_id: Option<String>,
}
```

`Entry` is shared by both arrays. There is no `level`/`severity` (the array is the MUST/SHOULD distinction), no `properties` (one entry per property), and no `expected`/`got` (the message carries the detail). `Outcome` serializes to `{valid, value?, errors, warnings}`.

Alternatives considered:

- Separate `ErrorEntry` and `WarningEntry`: rejected — same wire shape, two parsers, two catalogs.
- Constructors returning `Outcome`: rejected — breaks the documented object-or-raise ergonomics, makes `value` optional at every call site, and replaces Python's exception idiom with return-code handling.
- Recompute warnings on a getter: rejected — repeats validation.

### D2: Explicit `CheckContext`, no ambient sink

```rust
pub trait Stix {
    fn check(&self, ctx: &mut CheckContext) -> Result<(), StixError>;

    fn stix_check(&self) -> Result<(), StixError> {
        self.check(&mut CheckContext::discard())
    }

    fn outcome(&self) -> Outcome<()> { /* check + collect */ }
}
```

`CheckContext` holds the warning vector and the current `object_id` (used to stamp entries). It is stack-local per validation call, so there is no leakage and no thread-local cleanup. The compiler forces every call site to thread `ctx`; a forgotten path fails to compile rather than silently dropping warnings. `stix_check()` remains for Rust compatibility and discards warnings.

Alternatives considered:

- Thread-local sink: rejected — hidden state, silent loss if an entry point is not wrapped, test pollution.
- `log` capture: rejected — string-only, no structure, conflicts with host loggers.
- Separate warning traversal: rejected — two passes and drift risk.

### D3: Single semantic pass

`stix_check`/`check` is the single semantic gate. The builder's present-but-empty checks move into `check`, so one pass covers structural presence (registry), serde, and semantic rules.

- `build_no_validate` becomes pure assembly (id generation, timestamp defaults, struct construction). It no longer checks required fields. It stays for `to_json()`.
- `build()` = assemble + `check`; `build_outcome()` returns the outcome.
- Python constructors: `validate_value_outcome` → `from_parsed` → wrapper. Delete `validate_sdo_builder`, `validate_sco_builder`, `validate_sro_builder`, `validate_marking_builder`.
- `from_json` uses the same pipeline, so empty required strings behave identically to constructors.
- Bundle: deserialize raw object `Value`s, validate each once via the outcome pipeline, aggregate warnings, then run bundle invariants only. `Bundle::stix_check` remains the full check for programmatic bundles.
- Entry dedupe keyed by `(object_id, kind, property, value)` guards against any remaining repeated rule.

`validate_value` and the existing `parse_*`/`from_json`/`build`/`Bundle::from_json` `Result` APIs remain as warning-discarding wrappers so Rust callers do not all have to change; the outcome variants are used by bindings.

### D4: Spec-aligned classification and warning catalog

MUST → errors; SHOULD → warnings. Open-vocabulary membership was audited against the local spec: every property the engine checks is SHOULD, except `hash-algorithm-ov`, where the `hashes` type says keys MUST come from the vocabulary (with `x_` custom keys). Closed enums stay errors.

Warning catalog (12 kinds):

| kind | basis | fields | meaning |
|---|---|---|---|
| `hash_not_sha256` | SHOULD §2.7 | `property`, `value`, `object_id` | hash algorithm other than SHA-256 |
| `dictionary_key_not_lowercase` | SHOULD §2.3 | `property`, `value`, `object_id` | uppercase key where the property does not require case preservation |
| `extension_key_not_extension_definition` | SHOULD §3.2 | `property`, `value`, `object_id` | extension key is not an extension-definition id or a recognized predefined extension |
| `external_reference_url_without_hashes` | SHOULD §2.5 | `property`, `value`, `object_id` | URL present without `hashes` |
| `network_traffic_missing_port` | SHOULD §6.12 | `property`, `object_id` | `src_port` or `dst_port` missing (one entry per missing port) |
| `protocol_missing_from_protocols` | SHOULD §6.12 | `property`, `value`, `object_id` | protocol extension present but protocol absent from `protocols` |
| `relationship_type_not_suggested` | SHOULD §5.1 | `property`, `value`, `object_id` | custom relationship type |
| `marking_definition_type_not_suggested` | SHOULD §7.2.1.1 | `property`, `value`, `object_id` | `definition_type` not `tlp`/`statement` |
| `observed_data_unrecognized_ref` | unverifiable §4.14 | `property`, `value`, `object_id` | `object_refs` entry type not recognized |
| `observed_data_no_recognized_sco` | unverifiable §4.14 | `property`, `object_id` | no recognized SCO in `object_refs` |
| `open_vocab_value_not_suggested` | SHOULD §2.14 | `property`, `value`, `vocabulary`, `object_id` | open-vocab value not in the suggested vocabulary |
| `value_not_lowercase_hyphenated` | SHOULD §2.14/§2.11 | `property`, `value`, `object_id` | non-suggested open-vocab term or kill-chain value not lowercase/hyphenated |

Error kinds are cleaned up at the same time:

- Remove dead variants: `unknown_fields`, `bad_version`, `parse_integer_error` (no reachable call sites outside `error/mod.rs`).
- Merge `missing_builder_property` into `missing_property` during the pass collapse.
- Map `date_time_error`/`parse_timestamp_error` to `invalid_timestamp`; `parse_identifier_error` already maps to `invalid_identifier`.
- Rename `parse_hex_error` to `invalid_hex`.
- Hash-key membership uses `invalid_vocab_value` with `vocabulary: "hash-algorithm-ov"` (or `invalid_hash`) rather than the generic `validation_error`.
- The docs catalog becomes exhaustive: `kind`, array, basis, fields, meaning, spec reference. A `KNOWN_ERROR_KINDS` const plus the existing `all_variants()` test guards drift; a per-kind warning test guards warnings.

### D5: Non-spec strictness fixes

- **Key length**: hash keys and dictionary keys accept up to 250 ASCII characters (§2.3, §2.7). Remove both 30-character checks.
- **Dictionary case**: remove the blanket uppercase warning from `StixDictionary::stix_check`; emit `dictionary_key_not_lowercase` at the property level for `extensions` (and any future dictionary without a case rule). Case-preserved dictionaries are exempt: EXIF `exif_tags` (MUST), `startup_info` (MUST), IPFIX, HTTP `request_header`, email `headers`, PDF `document_info_dict`, socket `options`, language-content keys, process `environment_variables`. A declarative per-property key-case policy was considered but rejected as a larger type change; property-level emission is sufficient for the current dictionary set.
- **SHA-256 comparison**: compare the normalized algorithm, so `sha-256` does not warn as non-SHA-256.
- **Vocabulary names**: custom-message sites report the spec vocabulary names (`pattern-type-ov`, `malware-type-ov`, `account-type-ov`).
- **Language tags**: validate `CommonProperties.lang` and `Software.languages` with `LanguageTag::parse` (well-formedness) instead of `validate()` (incomplete registry). Delete `cyber_observable_objects/lang_codes.rs` and its exports. Accept ISO 639-2 codes such as `eng`. RFC 5646 registration is a SHOULD; rejecting valid codes is worse than accepting unregistered well-formed tags.
- **HTTP headers**: remove the fixed `HTTP_REQUEST_HEADERS` list; accept any valid header field name and do not apply the lowercase warning (§6.12.2 says headers SHOULD preserve case).
- **Warnings only in `check`**: the SHA-256 and dictionary-case warnings move out of construction/setter helpers (`check_hash_key`, `check_dictionary_key`) into `check`, so the single pass collects them exactly once.

### D6: Python surface

- Wrapper structs gain a second tuple field: `pub struct Campaign(pub DomainObjectBuilder, pub Vec<Entry>)`. `self.0` stays, so the 120 existing accesses are untouched; `.warnings` is a getter over `self.1`.
- `stix_to_pyerr(error, warnings)` sets both `.errors` and `.warnings` on the exception.
- `wrap_stix_object(py, obj, warnings)` carries per-object warnings into bundle children.
- Python stays exception-based: MUST violations raise, SHOULD findings ride on the returned object or the exception. The Rust `Outcome` remains available to other bindings, which can choose a return-code or exception model.
- `strict=True`: MUST errors, SHOULD warnings. `strict=False`: no semantic checks, so no errors and no warnings. Structural checks (required presence, unknown properties, serde) still apply.

### D7: Documentation and cross-language contract

- README: spec-first wording. Do not add the proposed `--strict`/reference-validator sentence. Remove the reference-validator framing from the existing "Known divergences" section and the "Battle-tested… parity against cti-stix-validator" bullet; keep the technical notes as spec-conformance notes without naming the validator.
- `docs/guides/validation.md`: `strict=True` vs `strict=False`, warnings, and the object/exception mapping.
- `docs/guides/errors.md`: one entry shape, errors + warnings catalog, and `.warnings`.
- `.pyi`: `.warnings` on the object bases and exception hierarchy.
- `testdata/test_matrix.json`: `expected_warnings` on entries and warning fixtures so every binding asserts the same kinds.
- Tests: Rust per-kind warning tests and message-detail assertions for the fields removed from the wire (`expected`/`got`); Python tests for `.warnings`, exception warnings, `strict=False`, bundle attribution, and dedupe; matrix parity.
- Benchmarks: compare constructor and parse benchmarks before/after. The collapse should improve construction; the context adds a lazily-allocated `Vec` that costs nothing when no warnings fire.

### D8: Version bump

`rust/Cargo.toml` and `pyproject.toml` move from `0.1.0` to `0.1.1`; regenerate `uv.lock`. Bump `rust/stixflayer_derive/Cargo.toml` in lockstep and update the main crate's `version = "0.1.0"` dependency requirement, or leave the derive crate at `0.1.0` if it has no changes. The release gate compares the manifest version to the latest tag, so `0.1.1 > 0.1.0` triggers a release; docs deploy collapses `0.1.1` to the `0.1` line.

## Risks / Trade-offs

- **Large mechanical refactor** (84 `Stix` impls, ~290 `.stix_check()` call sites) → the compiler enforces `ctx` threading; use GritQL for the mechanical rename; land in the staged order below; keep tests and benchmarks green at each stage.
- **Behavior change for open-vocabulary values** (no longer raise) → pre-release, no migration debt; update docs, stubs, matrix, and tests; call it out in release notes.
- **Removing non-spec strictness accepts documents previously rejected** → intended spec adherence; add fixtures for the newly accepted cases (31-char keys, `eng`, custom HTTP headers).
- **Warning false positives** → the dictionary case policy and the warning catalog are tested per kind; case-preserved dictionaries have explicit no-warning tests.
- **Warning false negatives** → the catalog is the contract; the drift test and matrix catch missing kinds. Unimplemented SHOULDs remain a known coverage gap (item 8).
- **Bundle attribution/dedupe** → every entry carries `object_id`; dedupe is keyed on it; bundle tests assert one warning per object.
- **Language validation is well-formedness, not registry membership** → documented; a registry-valid-only mode would need a complete IANA source and is out of scope.
- **`language_tags` parser quirks** → pin tests for `eng`, `en`, `en-US`, `zh-Hant-TW`, and malformed input; switch to ICU4X only if the parser proves insufficient.
- **Bundle deserialization still flattens object errors into serde strings** → the bundle restructure is the moment to preserve structured errors; if that proves too invasive, keep the flattening and note it as a follow-up.

## Migration Plan

Pre-release; no external users. Land in stages, each green on `cargo test`, `pytest`, clippy, and the benchmark gate:

1. Introduce `Entry`/`Outcome`/`CheckContext` and thread `ctx` through the trait and all call sites; keep `stix_check()` as a warning-discarding wrapper.
2. Move builder required/empty checks into `check`; make `build_no_validate` assembly-only; add outcome-returning entry points.
3. Collapse Python constructors and `from_json` onto the single pipeline; delete the `validate_*_builder` helpers.
4. Collapse the bundle path and pass per-object warnings through `wrap_stix_object`.
5. Replace `warn!` sites with `ctx.warn`; apply the reclassification and the non-spec strictness fixes; delete `lang_codes.rs`.
6. Add `.warnings`, exception `.warnings`, stubs, docs, matrix, and tests.
7. Bump versions and run the full gate.

Rollback is a plain revert; nothing external depends on the new behavior yet.
