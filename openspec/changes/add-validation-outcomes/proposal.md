# Proposal

## Why

Issue #17: the engine currently emits SHOULD-level findings through `log::warn!`, which Python callers never see because no logger bridge is installed, and several SHOULD rules are enforced as hard errors — rejecting valid STIX 2.1 (for example, open-vocabulary values, which the spec says MAY be any string). Bindings need a language-agnostic result envelope on the return path, symmetric with the existing input envelope, so each language can decide how to surface warnings. The project is pre-release, so this is the moment to make the breaking API changes required for correctness.

## What Changes

- **Outcome return contract** — the core computes `Outcome<T> { valid: bool, value: Option<T>, errors: Vec<Entry>, warnings: Vec<Entry> }`, serializable to JSON. One sparse `Entry` shape is shared by both arrays: `kind`, `message`, `property?`, `value?`, `vocabulary?`, `object_id?`. No `level` (the array is the MUST/SHOULD distinction), no `properties` (one entry per property), no `expected`/`got` (the message carries the detail).
- **Explicit validation context** — warnings are threaded through `Stix::check(&self, ctx: &mut CheckContext)`. No ambient sink or thread-local state. `stix_check()` remains as a compatibility wrapper that discards warnings.
- **Single semantic pass** — collapse the duplicate `stix_check` calls in Python constructors and bundle parsing. `stix_check` becomes the single semantic gate (absorbing the builder's present-but-empty checks); `build_no_validate` becomes assembly-only; entries are deduplicated. This also fixes the current constructor/`from_json` divergence where `from_json` accepts an empty required string that the constructor rejects.
- **Spec-aligned classification** — MUST violations are errors; SHOULD violations are warnings and never raise. Open-vocabulary membership, dictionary-key case, kill-chain format, and non-suggested open-vocab formatting become warnings. Closed enums stay errors. `hash-algorithm-ov` keys stay errors because the `hashes` type imposes a MUST. `observed_data` custom-reference findings are documented as "unverifiable", not SHOULD.
- **Remove non-spec strictness** — replace two 30-character dictionary-key limits with the spec's 250; scope the dictionary lowercase warning per property so case-preserved dictionaries (EXIF, `startup_info`, IPFIX, HTTP headers, email headers, PDF info, socket options, language tags, environment variables) are not flagged; compare SHA-256 case-insensitively; report the correct spec vocabulary names (`pattern-type-ov`, `malware-type-ov`, `account-type-ov`).
- **RFC 5646 language validation** — validate both `CommonProperties.lang` and `Software.languages` as well-formed RFC 5646 tags instead of using `language_tags::LanguageTag::validate()` (whose IANA registry is incomplete and rejects valid codes such as `eng`) or the fixed `stix2validator` language lists. Delete `lang_codes.rs`.
- **Remove the fixed HTTP request-header list** — accept any valid header field name; do not apply the lowercase dictionary warning because the spec says headers SHOULD preserve case.
- **Python surface** — constructors and `from_json` return the object with `.warnings`; exceptions expose `.errors` and `.warnings`; a non-raising `check()` returns the raw `Outcome`. `strict=True` runs semantic checks (MUST errors, SHOULD warnings); `strict=False` skips semantic checks entirely, so there are no warnings. **BREAKING** for Python: open-vocabulary values no longer raise, the `.errors` entry shape changes, and `.warnings` is new. Pre-release, no migration burden.
- **Documentation and contract** — extend the error catalog into an errors + warnings catalog with `kind`, basis, fields, meaning, and spec reference; document the strict/warn model; add `expected_warnings` and warning fixtures to the shared test matrix; add drift tests for known kinds. README stays spec-first and does not mention the reference validator.
- **Version bump** — `rust/Cargo.toml` and `pyproject.toml` move from `0.1.0` to `0.1.1` (with `uv.lock` regenerated) so the release goes out.

## Capabilities

### New Capabilities

- `validation-outcomes`: the cross-language result contract — `Outcome<T>`, the shared `Entry` shape, warning kinds and their spec basis, explicit `CheckContext` threading, single-pass validation, and the MUST/SHOULD classification rules.

### Modified Capabilities

- `error-reporting`: exceptions now carry `.warnings`; vocabulary violations split into closed-enum errors and open-vocabulary warnings; the `.errors` entry shape changes (one `property`, no `properties`/`expected`/`got`, new `object_id`); SHOULD violations never raise.
- `python-api`: `.warnings` on objects and exceptions and the non-raising `check()` become supported public entry points, and the `.pyi` stubs must cover them.

## Impact

- **Rust code**: `error/` (entry/outcome types, kinds), `stix.rs` (`Stix` trait, common properties), `validation.rs` (single-pass gate), every `Stix` impl and `.stix_check()` call site, all builders, `bundles/`, `dictionary.rs`, `hashes.rs`, `software.rs`, `extensions/network_traffic.rs`, `cyber_observable_objects/lang_codes.rs` (delete), and `python_bindings/`.
- **Python surface**: object and exception `.warnings`, `check()`, changed `.errors` fields, changed behavior for open-vocabulary values.
- **Rust surface**: **BREAKING** `Stix` trait method signature; new `Outcome`/`Entry`/`CheckContext` types; outcome-returning variants of the parse/build entry points; existing `Result` APIs retained as warning-discarding wrappers.
- **Docs/stubs**: `README.md`, `docs/guides/errors.md`, `docs/guides/validation.md`, `src/stixflayer/*.pyi`, `testdata/test_matrix.json`, `tests/`, `benchmarks/`.
- **Dependencies**: no new runtime dependencies; `language_tags` is already present and used for RFC 5646 parsing.
- **Out of scope**: unimplemented SHOULDs such as extension-definition `description`/`url`/`extension_properties` (separate coverage audit); pyo3-log or other logging bridges; pattern grammar changes; new language bindings.
