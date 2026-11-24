# Design

## Context

See `proposal.md` — Why. Current state that shapes the approach:

- `HttpRequestExtension.request_header` is `Option<StixDictionary<String>>` in `rust/src/extensions/network_traffic.rs`.
- `StixDictionary<Vec<String>>` is already the model for other repeated-value dictionaries: `EmailMessage.additional_header_fields` and `Process.startup_info`.
- `dict_to_extension` deserializes the raw extension dictionary with serde, so the value type is enforced before `check()` runs.
- Two Rust tests currently encode the wrong behavior: `deserialize_network_traffic_http_dict` uses string values, and `deserialize_network_traffic_http_request_invalid_header` asserts that list values are invalid.
- The original OASIS Standard's §6.12.2.1 example shows bare string values, contradicting the normative MUST in the same section. STIX 2.1 Errata 01 (02 April 2025) corrects the example to lists of strings. The engine already models `EmailMessage.additional_header_fields` as `StixDictionary<Vec<String>>` under the same normative wording.

## Goals / Non-Goals

**Goals:**

- Accept the STIX 2.1 `request_header` shape: header name to list of string values.
- Reject a bare string value.
- Keep header names unrestricted and case-preserved.
- Lock the behavior with Rust, fixture-matrix, and Python-level coverage.
- Correct the public conformance note.

**Non-Goals:**

- Changing any other network-traffic extension or dictionary property.
- Accepting both string and list values for compatibility.
- Adding a CLI flag or a Python-specific workaround.
- Changing error entry shapes or introducing a new error kind.

## Decisions

### D1: Use `StixDictionary<Vec<String>>`

This is the existing model for repeated header-style values (`additional_header_fields`, `startup_info`). It gives serde-enforced list values, per-item `String` validation, and unchanged key validation for free. A custom wrapper type would duplicate that behavior without adding anything.

*Alternative rejected:* `StixDictionary<DictionaryValue>` with a manual list check. It would defer the shape error to validation and allow non-string list members unless checked again.

### D2: Reject string values instead of accepting both shapes

STIX 2.1 §6.12.2 says each value MUST be a list of strings. Accepting a bare string would keep the engine permissive toward non-conformant input, which is the opposite of the project's positioning. The crate is pre-1.0, so a direct Rust API break is acceptable.

The original section's example used bare strings, but an example does not override a MUST in the same property table; STIX 2.1 Errata 01 (02 April 2025) corrects that example to lists of strings. `EmailMessage.additional_header_fields` has the same normative wording and the engine already follows the normative text there, so this change makes `request_header` consistent with it.

*Alternative rejected:* a custom deserializer that accepts `String` and wraps it in a one-element list. It preserves compatibility but makes a non-conformant document validate, and it hides the shape error from users.

### D3: Update the test that asserted list values are invalid

`deserialize_network_traffic_http_request_invalid_header` currently treats `["gzip,deflate"]` as the invalid case. That test encodes the bug, so it becomes the string-value rejection test. `deserialize_network_traffic_http_dict` switches to list values and asserts they round-trip.

### D4: Cover both the engine and the fixture matrix

The Rust unit tests prove the serde shape. A valid fixture with one single-value header and one repeated header, plus an invalid fixture with a bare string, give the language-agnostic matrix the same regression coverage every binding uses. A Python test validates the spec-conformant shape through the shared engine, because the Python package is the primary consumer.

### D5: Correct the conformance page in the same change

`docs/guides/conformance.md` currently says only that header names are unrestricted. It should also state the list-of-strings value rule and cite §6.12.2, so the public page matches the code. The `reposition-python-first` review note that recorded the gap can be marked addressed.

## Risks / Trade-offs

- **Breaking direct Rust constructors** → callers change `"value".to_string()` to `vec!["value".to_string()]`; document the break in the release notes and keep the change scoped to the pre-1.0 API.
- **Python users sending string values now get an error** → this is the spec-correct verdict; the error is a deserialization failure, and the conformance page explains the required shape.
- **Generic serde error for a string value** → tests assert rejection rather than an exact message; a more specific `invalid_property_type` entry can be a later improvement if users ask.
- **Fixture drift** → the valid and invalid fixtures plus matrix rules make the shape a permanent regression test.

## Migration Plan

No persisted state changes. Update the type, tests, fixtures, and docs in one change. Rollback is a revert. At release time, treat the Rust constructor change as breaking and bump the minor version.

## Open Questions

None.
