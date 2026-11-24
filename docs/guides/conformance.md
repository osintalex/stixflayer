# Conformance

The [OASIS STIX 2.1 specification](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)
is authoritative. stixflayer follows its MUST/SHOULD distinction rather than
the behaviour of any single implementation, and the notes below record the
places where that is easy to get wrong.

## MUST and SHOULD

STIX 2.1 [§12 Conformance](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_difggtnnudht)
defines mandatory and recommended behaviour. stixflayer enforces the two
separately:

- MUST violations are errors and reject the document.
- SHOULD findings are warnings and never reject a document.

Objects returned by constructors and `from_json` expose `.warnings`;
exceptions expose both `.errors` and `.warnings`. The CLI reports warnings
without changing the exit code unless `--fail-on-warnings` is set. The
`expected_warnings` entries in `testdata/test_matrix.json` exercise the
warning path.

## Requiredness follows the property tables

Optional properties are accepted when absent, and conditional requirements
apply only when their condition holds. In particular:

- `Indicator.name` is optional ([§4.7.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wfiae74706sw)).
- `Malware.name` is required only for a malware family, when `is_family` is
  `true` ([§4.11.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gc4ooz6oaz7y)).
- A missing required property produces one `missing_property` finding per
  absent field; present fields are not reported.

The regression fixtures are `testdata/stix/valid/sdo/indicator-no-name.json`,
`testdata/stix/valid/sdos/malware-instance-no-name.json`, and
`testdata/stix/invalid/sdo/indicator-no-valid-from.json`, with matching rules
in `testdata/test_matrix.json`.

## Spec notes

### Dictionary keys allow up to 250 characters

STIX 2.1 [§2.3 Dictionary](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_f6e8afjdtrse)
caps dictionary keys at 250 ASCII characters and says they SHOULD be
lowercase. stixflayer accepts keys up to that limit and reports uppercase
`extensions` keys as the `dictionary_key_not_lowercase` warning rather than
rejecting them. The length rule is covered by the
`dictionary_keys_allow_up_to_250_characters` unit test in `rust/src/dictionary.rs`.

### Language tags are well-formed RFC 5646 values

The common `lang` property ([§3.2 Common Properties](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_xzbicbtscatx))
and `Software.languages` ([§6.14 Software](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_7rkyhtkdthok))
must be well-formed RFC 5646 tags. Both accept ISO 639-2 three-letter codes
such as `eng`; registry membership is a SHOULD. `testdata/stix/invalid/common/invalid-language.json`
covers the rejection path.

### HTTP header names are unrestricted and values are lists of strings

[§6.12.2 HTTP Request Extension](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_b0e376hgtml8)
defines `request_header` as a dictionary whose keys are header field names and
does not restrict them to a fixed list. stixflayer accepts any valid dictionary
key and preserves case. Each header value MUST be a list of strings, so a
repeated header such as `X-Forwarded-For` can be represented; a bare string
value is rejected with a deserialization error. STIX 2.1 Errata 01 corrects the
original section's bare-string example to match this normative rule. See the
comment and check in `rust/src/extensions/network_traffic.rs`, plus the
`http-request-header-values-valid` and `http-request-header-string-invalid`
rules in `testdata/test_matrix.json`.

### Zero qualifier values are rejected

[§9.5.1 Observation Expression Qualifiers](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_itrc2pdxk4ef)
requires `REPEATS` to be a positive integer and `WITHIN` to be a positive
value. stixflayer rejects `REPEATS 0` and `WITHIN 0`; both are covered by
`testdata/stix/invalid/patterns/semantic.json`.

### Hash values in patterns are not inspected

Pattern validation follows the grammar and comparison rules. A hash value is a
string comparison ([§9.6.4 Native Format Comparison](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_de6g573394q2)),
so the validator does not inspect the hash format. Fixture `V46` in
`testdata/stix/valid/patterns/grammar-edges.json` covers this.

### Leading block comments are skipped

[§9.3 STIX Patterns](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_me3pzm77qfnf)
allows comments in a pattern. A pattern may start with a block comment because
the grammar skips comments. Fixture `V31` in
`testdata/stix/valid/patterns/grammar-edges.json` covers this.

### Negative list indices are accepted

The grammar accepts a negative integer index, so an index such as
`body_multipart[-1]` validates. [§9.7.2 List Object Properties](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_tqad81km2lrm)
defines the index form as `0...N-1` or `*`; the parser is deliberately
compatible with the grammar here. Fixture `V38` in
`testdata/stix/valid/patterns/grammar-edges.json` covers this.

### Custom SCO type casing

A custom SCO type name must be 3-250 characters of lowercase ASCII letters,
digits, or hyphens ([§11.2 Custom Objects](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_7f3c4jgkyhl3)).
The rule is implemented in `ObjectPath::validate` in `rust/src/pattern/expr.rs`;
`testdata/stix/valid/patterns/spec-examples.json` includes a custom SCO path.

### Reversed or empty `START`/`STOP` ranges

[§9.5.1 Observation Expression Qualifiers](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_itrc2pdxk4ef)
defines the matched range as `x <= observation < y` but does not prohibit
`x >= y`. Reversed and equal ranges are accepted. Both cases are covered by
`testdata/stix/valid/patterns/compliance.json`.

## Tested against public feeds

The validator is checked against three public STIX 2.1 data sets. The commands
below are reproducible with a downloaded copy of each file:

```console
stixflayer --json malware.stix2
stixflayer --json cellebrite.stix2
stixflayer --json enterprise-attack.json
```

| Feed | Objects | Result |
|---|---|---|
| [Amnesty International IOC feed](https://raw.githubusercontent.com/AmnestyTech/investigations/master/2023-03-29_android_campaign/malware.stix2) | 4,375 | 0 errors, 0 warnings |
| [MVT Cellebrite indicators](https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/cellebrite/cellebrite.stix2) | 3 | 0 errors, 1 warning |
| [MITRE ATT&CK Enterprise](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json) | 26,699 | exit `1`: 1,575 errors, 41,609 warnings |

### Amnesty: Indicators without a name

The Amnesty feed contains Indicators that omit `name`. `name` is optional for
Indicators ([§4.7.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wfiae74706sw)),
so the feed validates with no findings. The `amnesty-indicator-bundle-valid`
rule and its fixture reproduce the shape without vendoring the feed.

### MVT: a UUIDv5 relationship identifier

The MVT feed validates with no errors and one `identifier_uuid_not_v4`
warning. [§2.9 Identifier](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_64yvzeku5a5c)
says SDO, SRO, Meta, and Bundle identifiers SHOULD use UUIDv4, not MUST. The
relationship identifier is therefore a SHOULD finding; `--fail-on-warnings`
turns it into exit `1`. `stix2` also accepts the feed.

### MITRE ATT&CK: strict relationship shapes

ATT&CK's `x-mitre-*` custom objects are accepted and produce
`custom_missing_extension` warnings, because [§11.2](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_7f3c4jgkyhl3)
makes the `new-sdo`/`new-sco`/`new-sro` extension a SHOULD.

The reported errors are intentional strictness. [§5.1 Relationship](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_e2e1szrqfoan)
says a Relationship links two SDOs or SCOs; the `x-mitre-*` objects do not
declare an extension that makes them SDOs. [§4.1.2](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_axjijf603msy)
does not list `tool -> attack-pattern` for `uses`, and undefined pairs should
use `related-to` or a user-defined relationship name. The CLI has no flag to
accept non-conformant relationship shapes.

Ecosystem behaviour is mixed here: `stix2-validator` also rejects a minimal
custom object without an extension, because it cannot locate a base schema.
