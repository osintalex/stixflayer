# Error handling

Two exceptions cover every failure. Both carry a structured `errors` list —
never just a string.

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
| `ValidationError` | The JSON parses but violates STIX 2.1 rules — missing properties, unknown properties, bad vocabulary values, invalid patterns |

Both are subclasses of `StixError`, so `except StixError` catches everything.

## Anatomy of an error entry

Every entry has a `kind` and a human-readable `message`. Most kinds add
contextual fields, so you can branch on structured data instead of parsing
messages.

```python
from stixflayer import Identity, ValidationError

try:
    Identity(
        id="identity--c78b4a5a-3b42-4f2e-9b1a-7f8e9d0c1a2b",
        name="Acme Corp",
        spec_version="2.1",
        created="2019-04-24T15:12:36.609Z",
        modified="2023-03-24T15:14:15.637Z",
        identity_class="bogus-class",
    )
except ValidationError as e:
    entry = e.errors[0]
    print(entry["kind"], "|", entry["vocabulary"], "|", entry["value"])
    #> invalid_vocab_value | identity-class-ov | bogus-class
```

## Error catalog

| Kind | Extra fields | Meaning |
|---|---|---|
| `missing_property` | `property` | A required property is absent |
| `unknown_property` | `properties` | Property names outside the specification |
| `invalid_property_type` | `property`, `expected`, `got` | A property has the wrong JSON type |
| `invalid_vocab_value` | `value`, `vocabulary` | Value not in its STIX vocabulary |
| `invalid_hash` | `value`, `expected`, `got` | Hash value doesn't match its algorithm |
| `invalid_timestamp` | `value` | Timestamp not in STIX 2.1 format |
| `invalid_identifier` | `value` | Malformed STIX identifier |
| `invalid_pattern` | `value`, `got` | STIX pattern fails to parse |
| `empty_list` | — | A list property or bundle contains no items |
| `deserialization_error` | — | Catch-all for input that can't be deserialized |

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

## Pattern errors

Invalid STIX patterns raise `ValidationError` with an `invalid_pattern`
entry carrying the pattern and the parse failure.

```python
import stixflayer

try:
    stixflayer.validate_pattern("[ipv4-addr:value = 192.0.2.1]")
except Exception as e:
    entry = e.errors[0]
    print(entry["kind"], "|", entry["value"])
    #> invalid_pattern | [ipv4-addr:value = 192.0.2.1]
```
