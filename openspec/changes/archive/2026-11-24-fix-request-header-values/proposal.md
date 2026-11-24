# Proposal

## Why

STIX 2.1 §6.12.2 defines `request_header` as a dictionary whose values MUST be lists of strings, so a repeated header can be represented. `HttpRequestExtension` currently models it as `StixDictionary<String>`, which rejects the spec-conformant list shape and accepts a single string. The engine is therefore wrong in both directions for a published HTTP extension property, and an existing Rust test asserts the incorrect behavior.

The original OASIS Standard's §6.12.2.1 example rendered header values as bare strings, contradicting the normative MUST; STIX 2.1 Errata 01 (02 April 2025) corrects that example to lists of strings. This change follows the normative text and the errata, matching how the engine already models `EmailMessage.additional_header_fields`.

This is a small, isolated conformance fix. It matters now because the `reposition-python-first` conformance page is public and cites HTTP header handling as evidence of spec correctness.

## What Changes

- Change `HttpRequestExtension.request_header` from `StixDictionary<String>` to `StixDictionary<Vec<String>>`.
- Update the extension's Rust tests so list values are accepted and string values are rejected.
- Add a valid fixture with repeated and single-value headers, and an invalid fixture with a string value, with matching `testdata/test_matrix.json` rules.
- Update `docs/guides/conformance.md` to state the value shape and link it to §6.12.2.
- **BREAKING** for Rust callers that construct `HttpRequestExtension` directly with string values; they must now pass `Vec<String>`. Python callers that send string values will now receive a validation error, which is the spec-correct result.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `validation-outcomes`: the existing HTTP request header requirement gains the value-shape rule from STIX 2.1 §6.12.2, in addition to the unrestricted-name rule.

## Impact

- **Rust**: `rust/src/extensions/network_traffic.rs`, its unit tests in `rust/src/cyber_observable_objects/sco/network_traffic.rs`, and `rust/tests/validation_outcomes.rs`.
- **Fixtures**: `testdata/stix/valid/scos/`, `testdata/stix/invalid/scos/`, and `testdata/test_matrix.json`.
- **Python**: no binding code changes; the shared engine now accepts the spec-conformant shape and rejects the string shape. A Python-level regression test covers the round-trip.
- **Docs**: `docs/guides/conformance.md`; the existing review note in `reposition-python-first` can be marked addressed.
- **CLI**: no code change; it inherits the corrected verdict.
