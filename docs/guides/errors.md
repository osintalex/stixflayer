# Error handling

Two exceptions cover every failure. Both carry a structured `errors` list and
a `warnings` list — never just a string.

```python
from stixflayer import DeserializationError, StixError, ValidationError

print(issubclass(ValidationError, StixError))
#> True
print(issubclass(DeserializationError, StixError))
#> True
```

| Exception | Raised when |
|---|---|
| `DeserializationError` | Input is not parseable as STIX JSON — malformed JSON, wrong types, or not a JSON object |
| `ValidationError` | The JSON parses but violates a STIX 2.1 MUST rule — missing properties, unknown properties, closed-enumeration values, invalid patterns |

Both are subclasses of `StixError`, so `except StixError` catches everything.
SHOULD recommendations never raise; they appear in `.warnings`.

## Anatomy of an entry

Every error and warning entry has the same sparse shape: a `kind` and a
human-readable `message`, plus optional `property`, `value`, `vocabulary`, and
`object_id` fields. There is no `level` or `severity` field — the containing
list is the MUST/SHOULD distinction.

```python
from stixflayer import Identity

identity = Identity(name="Acme Corp", identity_class="bogus-class")
warning = identity.warnings[0]
print(warning["kind"], "|", warning["vocabulary"], "|", warning["value"])
#> open_vocab_value_not_suggested | identity-class-ov | bogus-class
print(warning["property"], "|", warning["object_id"][:8])
#> identity_class | identity
```

## Catching by failure type

JSON that can't be understood at all raises `DeserializationError` —
including JSON that parses but isn't a STIX object.

```python
from stixflayer import DeserializationError, Identity

try:
    Identity.from_json("[1, 2, 3]")
except DeserializationError as e:
    print(e)
    #> Deserialization error: Expected a STIX object (JSON object), got array.
```

## Error catalog

| Kind | Extra fields | Meaning |
|---|---|---|
| `missing_property` | `property` | A required property is absent or empty |
| `unknown_property` | `property` | A property name outside the specification |
| `invalid_property_type` | `property` | A property has the wrong JSON type |
| `invalid_vocab_value` | `value`, `vocabulary` | Value outside a closed enumeration or the hash vocabulary |
| `invalid_hash` | `value` | Hash value doesn't match its algorithm |
| `invalid_timestamp` | `value` | Timestamp not in STIX 2.1 format |
| `invalid_identifier` | `value` | Malformed STIX identifier |
| `invalid_pattern` | `value` | STIX pattern fails to parse |
| `empty_list` | — | A list property or bundle contains no items |
| `invalid_nested_object` | — | An object-level check failed because of an inner error |
| `deserialization_error` | — | Catch-all for input that can't be deserialized |
| `serialization_error` | — | Catch-all for values that can't be serialized |

## Warning catalog

| Kind | Extra fields | Meaning |
|---|---|---|
| `hash_not_sha256` | `property`, `value`, `object_id` | Hash algorithm other than SHA-256 |
| `identifier_uuid_not_v4` | `property`, `object_id` | Non-SCO identifier uses UUIDv5; STIX 2.1 §2.9 recommends UUIDv4 (**SHOULD**) |
| `dictionary_key_not_lowercase` | `property`, `value`, `object_id` | Uppercase `extensions` key |
| `extension_key_not_extension_definition` | `property`, `value`, `object_id` | Extension key is not an extension-definition id or a recognized predefined extension |
| `external_reference_url_without_hashes` | `property`, `value`, `object_id` | URL present without `hashes` |
| `network_traffic_missing_port` | `property`, `object_id` | `src_port` or `dst_port` missing (one entry per missing port) |
| `protocol_missing_from_protocols` | `property`, `value`, `object_id` | Protocol extension present but protocol absent from `protocols` |
| `relationship_type_not_suggested` | `property`, `value`, `object_id` | Custom relationship type |
| `marking_definition_type_not_suggested` | `property`, `value`, `object_id` | `definition_type` not `tlp`/`statement` |
| `observed_data_unrecognized_ref` | `property`, `value`, `object_id` | `object_refs` entry type not recognized |
| `observed_data_no_recognized_sco` | `property`, `object_id` | No recognized SCO in `object_refs` |
| `open_vocab_value_not_suggested` | `property`, `value`, `vocabulary`, `object_id` | Open-vocabulary value not in the suggested vocabulary |
| `value_not_lowercase_hyphenated` | `property`, `value`, `object_id` | Non-suggested open-vocab term or kill-chain value not lowercase/hyphenated |

## Pattern errors

Invalid STIX patterns raise `ValidationError` with an `invalid_pattern`
entry carrying the pattern and a parse message.

```python
import stixflayer

try:
    stixflayer.validate_pattern("[ipv4-addr:value = 192.0.2.1]")
except Exception as e:
    entry = e.errors[0]
    print(entry["kind"], "|", entry["value"])
    #> invalid_pattern | [ipv4-addr:value = 192.0.2.1]
```
